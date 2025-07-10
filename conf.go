package flash_sell

import (
	"context"
	"encoding/json"
	"flash_sell/utils"
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"github.com/gomodule/redigo/redis"
	etcd "go.etcd.io/etcd/client/v3"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

type FlashSellConf struct {
	redisConf        RedisConf
	etcdConf         ETCDConf
	logConf          LogConf
	etcdProductInfos []ETCDProductInfo
	lock             sync.RWMutex
}

type ETCDProductInfo struct {
	ProductId int       `json:"product_id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Status    int       `json:"status"` // 0: 未上架, 1: 已上架, 2: 卖完, 3: 已删除
	Stock     int       `json:"stock"`
}

type RedisConf struct {
	addr        string
	maxIdle     int
	maxActive   int
	idleTimeOut time.Duration
}

type ETCDConf struct {
	addr        string
	dialTimeout time.Duration
	userName    string
	password    string
	key         string
}
type LogConf struct {
	path  string
	level string
}

var (
	gFlashSellConf *FlashSellConf
	pool           *redis.Pool
	etcdClient     *etcd.Client
)

func printRedisInfo(conn redis.Conn) error {
	logs.Info("===== 开始收集Redis信息 =====")
	isCluster, err := isRedisCluster(conn)
	if err != nil {
		return fmt.Errorf("检测Redis模式失败: %w", err)
	}

	if isCluster {
		return printClusterSummary(conn)
	}
	return printStandaloneSummary(conn)
}

func isRedisCluster(conn redis.Conn) (bool, error) {
	// 尝试执行集群命令
	_, err := conn.Do("CLUSTER", "INFO")
	if err == nil {
		return true, nil
	}

	// 检查错误类型
	errStr := err.Error()
	if strings.Contains(errStr, "cluster support disabled") {
		return false, nil
	}

	// 其他错误
	return false, err
}

func printClusterSummary(conn redis.Conn) error {
	clusterInfo, err := redis.String(conn.Do("CLUSTER", "INFO"))
	if err != nil {
		return fmt.Errorf("获取集群信息失败: %w", err)
	}

	clusterStats := utils.ParseInfo(clusterInfo)
	logs.Info("模式: Redis集群")
	logs.Info("集群状态: %s", clusterStats["cluster_state"])
	logs.Info("节点数量: %s", clusterStats["cluster_known_nodes"])
	logs.Info("已分配槽位: %s/16384", clusterStats["cluster_slots_assigned"])

	return printCommonRedisInfo(conn)
}

func printStandaloneSummary(conn redis.Conn) error {
	info, err := redis.String(conn.Do("INFO"))
	if err != nil {
		return fmt.Errorf("获取Redis信息失败: %w", err)
	}

	infoStats := utils.ParseInfo(info)
	logs.Info("模式: 单节点")
	logs.Info("版本: %s", infoStats["redis_version"])
	logs.Info("运行时间: %s 天", infoStats["uptime_in_days"])

	return printCommonRedisInfo(conn)
}
func printCommonRedisInfo(conn redis.Conn) error {
	// 获取内存信息
	memInfo, err := redis.String(conn.Do("INFO", "memory"))
	if err != nil {
		return fmt.Errorf("获取内存信息失败: %w", err)
	}
	memStats := utils.ParseInfo(memInfo)

	// 获取键空间信息
	keyspaceInfo, err := redis.String(conn.Do("INFO", "keyspace"))
	if err != nil {
		return fmt.Errorf("获取键空间信息失败: %w", err)
	}
	keyspaceStats := utils.ParseInfo(keyspaceInfo)

	// 获取清除策略
	configInfo, err := redis.Strings(conn.Do("CONFIG", "GET", "maxmemory-policy"))
	if err != nil || len(configInfo) < 2 {
		logs.Warn("获取清除策略失败: %v", err)
	} else {
		logs.Info("清除策略: %s", configInfo[1])
	}

	// 打印容量信息
	printCapacityInfo(memStats, keyspaceStats)
	return nil
}
func printCapacityInfo(memStats map[string]string, keyspaceStats map[string]string) {
	maxMemory, _ := strconv.ParseUint(memStats["maxmemory"], 10, 64)
	usedMemory, _ := strconv.ParseUint(memStats["used_memory"], 10, 64)

	logs.Info("===== 容量信息 =====")

	if maxMemory > 0 {
		memoryUsage := float64(usedMemory) / float64(maxMemory) * 100
		logs.Info("内存总量: %s", utils.FormatBytes(maxMemory))
		logs.Info("已用内存: %s (%.1f%%)", utils.FormatBytes(usedMemory), memoryUsage)
	} else {
		logs.Info("已用内存: %s", utils.FormatBytes(usedMemory))
		logs.Warn("警告: 未配置最大内存限制(maxmemory=0)")
	}

	// 键数量统计
	totalKeys := 0
	for key, value := range keyspaceStats {
		if strings.HasPrefix(key, "db") && strings.Contains(key, "keys") {
			if keys, err := strconv.Atoi(value); err == nil {
				totalKeys += keys
			}
		}
	}
	logs.Info("键总数: %d", totalKeys)

	// 内存碎片率
	if fragRatio, ok := memStats["mem_fragmentation_ratio"]; ok {
		if ratio, err := strconv.ParseFloat(fragRatio, 64); err == nil {
			logs.Info("内存碎片率: %.2f", ratio)
			if ratio > 1.5 {
				logs.Warn("警告: 内存碎片率过高(>1.5), 考虑重启Redis或设置activedefrag=yes")
			}
		}
	}

	// 过期键信息
	if expiredKeys, ok := memStats["expired_keys"]; ok {
		logs.Info("已过期键: %s", expiredKeys)
	}

	// 淘汰键信息
	if evictedKeys, ok := memStats["evicted_keys"]; ok {
		if evicted, _ := strconv.Atoi(evictedKeys); evicted > 0 {
			logs.Warn("淘汰键数: %s (内存不足导致键被淘汰)", evictedKeys)
		} else {
			logs.Info("淘汰键数: %s", evictedKeys)
		}
	}
}

func initLog() error {
	config := make(map[string]interface{})
	config["filename"] = gFlashSellConf.logConf.path
	switch strings.ToLower(gFlashSellConf.logConf.level) {
	case "debug":
		config["level"] = logs.LevelDebug
	case "info":
		config["level"] = logs.LevelInfo
	case "warn":
		config["level"] = logs.LevelWarn
	case "error":
		config["level"] = logs.LevelError
	default:
		config["level"] = logs.LevelInfo // 默认级别
	}
	config["console"] = true

	configStr, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("序列化日志配置失败: %w", err)
	}
	if err := logs.SetLogger(logs.AdapterFile, string(configStr)); err != nil {
		return fmt.Errorf("设置日志适配器失败: %w", err)
	}
	// 立即记录一条初始化日志
	logs.Info("===== 日志系统初始化成功 =====")
	logs.Info("日志文件: %s", gFlashSellConf.logConf.path)
	logs.Info("日志级别: %s", gFlashSellConf.logConf.level)
	return nil
}
func initRedis() error {
	logs.Info("===== 开始初始化Redis连接 =====")
	pool = &redis.Pool{
		MaxIdle:     gFlashSellConf.redisConf.maxIdle,
		MaxActive:   gFlashSellConf.redisConf.maxActive,
		IdleTimeout: gFlashSellConf.redisConf.idleTimeOut,
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", "localhost:6379")
		},
	}
	conn := pool.Get()
	defer conn.Close()

	if _, err := conn.Do("PING"); err != nil {
		logs.Error("Redis Ping失败: %v", err)
		return fmt.Errorf("Redis连接测试失败: %w", err)
	}
	logs.Info("Redis连接成功: %s", gFlashSellConf.redisConf.addr)

	// 打印Redis信息
	if err := printRedisInfo(conn); err != nil {
		logs.Warn("获取Redis信息失败: %v", err)
		// 不中断初始化，只记录警告
	}

	return nil
}
func initEtcd() (err error) {
	config := etcd.Config{
		Endpoints:   []string{gFlashSellConf.etcdConf.addr}, // etcd 节点地址
		DialTimeout: gFlashSellConf.etcdConf.dialTimeout,    // 连接超时时间
		Username:    gFlashSellConf.etcdConf.userName,       // 用户名（如果启用认证）
		Password:    gFlashSellConf.etcdConf.password,       // 密码（如果启用认证）
	}

	// 创建 etcd 客户端
	etcdClient, err = etcd.New(config)
	if err != nil {
		log.Fatalf("创建 etcd 客户端失败: %v", err)
	}
	//defer client.Close() // 确保程序退出时关闭连接 TODO无需关闭

	fmt.Println("成功连接到 etcd 集群")

	// 测试连接 - 获取 etcd 版本
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resp, err := etcdClient.Status(ctx, config.Endpoints[0])
	if err != nil {
		log.Fatalf("获取 etcd 状态失败: %v", err)
	}

	fmt.Printf("etcd 版本: %s\n", resp.Version)
	fmt.Printf("集群ID: %x\n", resp.Leader)
	fmt.Printf("存储大小: %d bytes\n", resp.DbSize)

	return nil
}
func loadConfig() (err error) {
	redisAddr := beego.AppConfig.String("redis_addr")
	redisMaxIdle, _ := beego.AppConfig.Int("redis_max_idle")
	redisMaxActive, _ := beego.AppConfig.Int("redis_max_active")
	redisIdleTimeout, _ := beego.AppConfig.Int("redis_idle_timeout")
	etcdAddr := beego.AppConfig.String("etcd_addr")
	etcdDialTimeout, _ := beego.AppConfig.Int("etcd_dial_timeout")
	etcdUserName := beego.AppConfig.String("etcd_user_name")
	etcdPassword := beego.AppConfig.String("etcd_password")
	etcdKey := beego.AppConfig.String("etcd_key")

	logPath := beego.AppConfig.String("log_path")
	logLevel := beego.AppConfig.String("log_level")

	if redisAddr == "" || etcdAddr == "" || logPath == "" {
		return fmt.Errorf("缺少必要配置: redis_addr=%s, etcd_addr=%s, log_path=%s", redisAddr, etcdAddr, logPath)
	}

	gFlashSellConf = &FlashSellConf{
		redisConf: RedisConf{
			addr:        redisAddr,
			maxIdle:     redisMaxIdle,
			maxActive:   redisMaxActive,
			idleTimeOut: time.Duration(redisIdleTimeout) * time.Second,
		},
		etcdConf: ETCDConf{
			addr:        etcdAddr,
			dialTimeout: time.Duration(etcdDialTimeout) * time.Second,
			userName:    etcdUserName,
			password:    etcdPassword,
			key:         etcdKey,
		},
		logConf: LogConf{
			path:  logPath,
			level: logLevel,
		},
	}
	logs.Info("配置信息: %+v", gFlashSellConf)
	return nil
}
func saveETCDConf() error {
	// save
	confs := []ETCDProductInfo{
		{
			ProductId: 1,
			StartTime: time.Date(2025, 7, 25, 13, 0, 0, 0, time.UTC),
			EndTime:   time.Date(2025, 7, 25, 13, 0, 0, 0, time.UTC).Add(time.Hour),
			Status:    1,
			Stock:     500,
		},
		{
			ProductId: 2,
			StartTime: time.Date(2025, 7, 25, 14, 0, 0, 0, time.UTC),
			EndTime:   time.Date(2025, 7, 25, 14, 0, 0, 0, time.UTC).Add(time.Hour),
			Status:    1,
			Stock:     300,
		},
	}
	data, err := json.Marshal(confs)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	// 保存到 etcd
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	key := fmt.Sprintf("%s/product", gFlashSellConf.etcdConf.key)
	_, err = etcdClient.Put(ctx, key, string(data))
	if err != nil {
		return fmt.Errorf("保存到etcd失败: %w", err)
	}
	logs.Info("保存秒杀配置成功, 商品ID0: %d, 路径: %s", confs[0].ProductId, key)
	return nil
}
func loadETCDConf() (err error) {
	key := fmt.Sprintf("%s/product", gFlashSellConf.etcdConf.key)
	resp, err := etcdClient.Get(context.Background(), key)
	if err != nil {
		logs.Error("get [%s] from etcd failed, err: %v", key, err)
		return err
	}
	for _, v := range resp.Kvs {
		logs.Debug("key: %s, value: %s", v.Key, v.Value)
	}
	// 反序列化为配置数组

	if err := json.Unmarshal(resp.Kvs[0].Value, &gFlashSellConf.etcdProductInfos); err != nil {
		return fmt.Errorf("解析配置失败: %w", err)
	}
	return nil
}
func watchETCDConf() error {
	key := fmt.Sprintf("%s/product", gFlashSellConf.etcdConf.key)
	logs.Info("开始监听配置变化: %s", key)

	rch := etcdClient.Watch(context.Background(), key)
	for resp := range rch {
		for _, ev := range resp.Events {
			switch ev.Type {
			case etcd.EventTypePut:
				logs.Info("检测到配置更新: %s", ev.Kv.Key)
				var newConfs []ETCDProductInfo
				if err := json.Unmarshal(ev.Kv.Value, &newConfs); err != nil {
					logs.Error("解析新配置失败: %v", err)
					continue
				}
				//gFlashSellConf.lock.Lock()
				gFlashSellConf.etcdProductInfos = newConfs
				//gFlashSellConf.lock.Unlock()
				logs.Info("配置更新成功! 新配置: %+v", newConfs)

			case etcd.EventTypeDelete:
				logs.Warn("配置被删除: %s", ev.Kv.Key)
				//gFlashSellConf.lock.Lock()
				gFlashSellConf.etcdProductInfos = []ETCDProductInfo{}
				//gFlashSellConf.lock.Unlock()
				logs.Warn("已清空秒杀配置")
			}
		}
	}
	return nil
}

func InitConfig() (err error) {
	// 1. 首先加载基本配置
	if err := loadConfig(); err != nil {
		return fmt.Errorf("加载配置失败: %w", err)
	}

	// 2. 立即初始化日志（最先初始化）
	if err = initLog(); err != nil {
		return fmt.Errorf("初始化日志失败: %w", err)
	}

	// 3. 使用日志记录配置信息
	logs.Info("===== 加载配置成功 =====")
	logs.Info("Redis地址: %s", gFlashSellConf.redisConf.addr)
	logs.Info("Etcd地址: %s", gFlashSellConf.etcdConf.addr)
	logs.Info("日志路径: %s", gFlashSellConf.logConf.path)
	logs.Info("日志级别: %s", gFlashSellConf.logConf.level)

	// 4.初始化redis
	if err := initRedis(); err != nil {
		return fmt.Errorf("初始化Redis失败: %w", err)
	}

	// 5. 初始化Etcd
	if err := initEtcd(); err != nil {
		return fmt.Errorf("初始化Etcd失败: %w", err)
	}

	// 6. ETCD配置写入和读取
	//if err = saveETCDConf(); err != nil {
	//	return fmt.Errorf("写入Etcd失败: %w", err)
	//}
	if err := loadETCDConf(); err != nil {
		return fmt.Errorf("读取Etcd失败: %w", err)
	}
	// 7. 启动ETCD配置监听
	go watchETCDConf()

	logs.Info("===== 所有组件初始化成功 =====")
	logs.Info("全局配置信息: %v", gFlashSellConf)
	return nil
}
