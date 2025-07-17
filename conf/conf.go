package conf

import (
	"context"
	"encoding/json"
	"errors"
	"flash_sell"
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

type Resp struct {
	Data      map[string]interface{} `json:"data"`
	ErrorCode int                    `json:"error_code"`
	ErrorMsg  string                 `json:"error_msg"`
}

type Req struct {
	ProductId int
	Source    string // 来源，安卓，苹果
	AuthCode  string
	FlashTime string // 抢购时间
	Nance     string
	// 1. 用户登录成功后，服务端设置两个cookie: userId和userAuth, md5(密钥+UserId)
	// 2. 抢购的时候需要用这两个cookie进行校验
	UserId       int
	UserAuthSign string
	AccessTime   time.Time // 访问时间
	ClientIp     string
	ClientRef    string // 用户从哪个页面进行的访问
}

type FlashSellConf struct {
	redisConf         RedisConf
	redisBlackConf    RedisConf // 存放黑名单的Redis
	etcdConf          ETCDConf
	logConf           LogConf
	EtcdProductInfos  map[int]ETCDProductInfo
	CookieSecretKey   string
	UserAccessLimit   int
	UserIpAccessLimit int
	ReferWhitelist    []string
	lock              sync.RWMutex
	IPBlackMap        map[string]bool
	UserIDBlackMap    map[int]bool
	redisBlackPool    *redis.Pool
	redisPool         *redis.Pool
	ReqChan           chan *Req
}

type ETCDProductInfo struct {
	ProductId int                      `json:"product_id"`
	StartTime time.Time                `json:"start_time"`
	EndTime   time.Time                `json:"end_time"`
	Status    flash_sell.ProductStatus `json:"status"` // 0: 未上架, 1: 已上架, 2: 卖完, 3: 已删除
	Stock     int                      `json:"stock"`
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
	GFlashSellConf *FlashSellConf
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
	config["filename"] = GFlashSellConf.logConf.path
	switch strings.ToLower(GFlashSellConf.logConf.level) {
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
	logs.Info("日志文件: %s", GFlashSellConf.logConf.path)
	logs.Info("日志级别: %s", GFlashSellConf.logConf.level)
	return nil
}
func initRedis() error {
	logs.Info("===== 开始初始化Redis连接 =====")
	pool = &redis.Pool{
		MaxIdle:     GFlashSellConf.redisConf.maxIdle,
		MaxActive:   GFlashSellConf.redisConf.maxActive,
		IdleTimeout: GFlashSellConf.redisConf.idleTimeOut,
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
	logs.Info("Redis连接成功: %s", GFlashSellConf.redisConf.addr)

	// 打印Redis信息
	if err := printRedisInfo(conn); err != nil {
		logs.Warn("获取Redis信息失败: %v", err)
		// 不中断初始化，只记录警告
	}
	GFlashSellConf.redisPool = pool

	return nil
}
func initEtcd() (err error) {
	config := etcd.Config{
		Endpoints:   []string{GFlashSellConf.etcdConf.addr}, // etcd 节点地址
		DialTimeout: GFlashSellConf.etcdConf.dialTimeout,    // 连接超时时间
		Username:    GFlashSellConf.etcdConf.userName,       // 用户名（如果启用认证）
		Password:    GFlashSellConf.etcdConf.password,       // 密码（如果启用认证）
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
func initRedisBlack() (err error) {
	logs.Info("===== 开始初始化黑名单Redis连接 =====")
	pool = &redis.Pool{
		MaxIdle:     GFlashSellConf.redisBlackConf.maxIdle,
		MaxActive:   GFlashSellConf.redisBlackConf.maxActive,
		IdleTimeout: GFlashSellConf.redisBlackConf.idleTimeOut,
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", GFlashSellConf.redisBlackConf.addr)
		},
	}
	conn := pool.Get()
	defer conn.Close()

	if _, err := conn.Do("PING"); err != nil {
		logs.Error("黑名单Redis Ping失败: %v", err)
		return fmt.Errorf("黑名单Redis连接测试失败: %w", err)
	}
	logs.Info("黑名单Redis连接成功: %s", GFlashSellConf.redisConf.addr)

	// 打印Redis信息
	if err := printRedisInfo(conn); err != nil {
		logs.Warn("获取黑名单Redis信息失败: %v", err)
		// 不中断初始化，只记录警告
	}
	reply, err := conn.Do("hgetall", "user_id_blacklist")
	if err != nil {
		logs.Warn("hget all failed, err: %v", err)
		return err
	}

	// 用户id黑名单加载
	userIdBlackList, err := redis.Strings(reply, err)
	if err != nil {
		logs.Warn("hget all failed from reply, err: %v", err)
		return err
	}
	for _, v := range userIdBlackList {
		id, err := strconv.Atoi(v)
		if err != nil {
			logs.Warn("hget convert id failed, err: %v", err)
			continue
		}
		GFlashSellConf.UserIDBlackMap[id] = true
	}
	// ip黑名单加载
	reply, err = conn.Do("hgetall", "ip_blacklist")
	IPBlackList, err := redis.Strings(reply, err)
	if err != nil {
		logs.Warn("IP hget all failed from reply, err: %v", err)
		return err
	}
	for _, ip := range IPBlackList {
		GFlashSellConf.IPBlackMap[ip] = true
	}

	// 同步ID
	go func(pool *redis.Pool) {
		var userIdBlackList []int
		lastUpDateTime := time.Now()
		for {
			conn = pool.Get()
			defer conn.Close()
			reply, err := conn.Do("BLPOP", "user_id_blacklist", time.Second)
			userId, err := redis.Int(reply, err)
			userIdBlackList = append(userIdBlackList, userId)
			if err != nil {
				continue
			}
			curTime := time.Now()

			// 每5秒更新或者用户名单超过10个
			if curTime.Sub(lastUpDateTime) > 5*time.Second || len(userIdBlackList) > 10 {
				for _, v := range userIdBlackList {
					// TODO 这里暂时没加锁,不清楚是否会报错
					GFlashSellConf.UserIDBlackMap[v] = true
				}
				logs.Info("从redis同步黑名单到全局map: %v", userIdBlackList)
			}
		}
	}(pool)

	// 同步黑名单
	go func(pool *redis.Pool) {
		var ipBlackList []string
		lastUpDateTime := time.Now()
		for {
			conn = pool.Get()
			reply, err := conn.Do("BLPOP", "ip_blacklist", time.Second)
			ip, err := redis.String(reply, err)
			ipBlackList = append(ipBlackList, ip)
			if err != nil {
				continue
			}
			curTime := time.Now()

			// 每5秒更新或者用户名单超过10个
			if curTime.Sub(lastUpDateTime) > 5*time.Second || len(ipBlackList) > 10 {
				for _, v := range ipBlackList {
					// TODO 这里暂时没加锁,不清楚是否会报错
					GFlashSellConf.IPBlackMap[v] = true
				}
				logs.Info("从redis同步IP黑名单到全局map: %v", ipBlackList)
			}
			conn.Close()
		}
	}(pool)
	GFlashSellConf.redisPool = pool
	return nil
}
func loadConfig() (err error) {
	redisAddr := beego.AppConfig.String("redis_addr")
	redisMaxIdle, _ := beego.AppConfig.Int("redis_max_idle")
	redisMaxActive, _ := beego.AppConfig.Int("redis_max_active")
	redisIdleTimeout, _ := beego.AppConfig.Int("redis_idle_timeout")

	redisBlackAddr := beego.AppConfig.String("redis_black_addr")
	redisBlackMaxIdle, _ := beego.AppConfig.Int("redis_black_max_idle")
	redisBlackMaxActive, _ := beego.AppConfig.Int("redis_black_max_active")
	redisBlackIdleTimeout, _ := beego.AppConfig.Int("redis_black_idle_timeout")

	etcdAddr := beego.AppConfig.String("etcd_addr")
	etcdDialTimeout, _ := beego.AppConfig.Int("etcd_dial_timeout")
	etcdUserName := beego.AppConfig.String("etcd_user_name")
	etcdPassword := beego.AppConfig.String("etcd_password")
	etcdKey := beego.AppConfig.String("etcd_key")

	logPath := beego.AppConfig.String("log_path")
	logLevel := beego.AppConfig.String("log_level")

	cookieSecretKey := beego.AppConfig.String("cookie_secret_key")
	userAccessLimit, _ := beego.AppConfig.Int("user_access_limit")
	referWhiteList := beego.AppConfig.Strings("refer_whitelist") // 默认使用;进行分割
	userIPAccessLimit, _ := beego.AppConfig.Int("user_ip_access_limit")

	if redisAddr == "" || redisBlackAddr == "" || etcdAddr == "" || logPath == "" || cookieSecretKey == "" || userAccessLimit == 0 || referWhiteList == nil || userIPAccessLimit == 0 {
		return fmt.Errorf("缺少必要配置: redis_addr=%s, etcd_addr=%s, log_path=%s, cookie_secret_key=%s, user_access_limit=%d, referWhiteList=%v, userIPAccessLimit=%v", redisAddr, etcdAddr, logPath, cookieSecretKey, userAccessLimit, referWhiteList, redisAddr, userIPAccessLimit)
	}

	GFlashSellConf = &FlashSellConf{
		redisConf: RedisConf{
			addr:        redisAddr,
			maxIdle:     redisMaxIdle,
			maxActive:   redisMaxActive,
			idleTimeOut: time.Duration(redisIdleTimeout) * time.Second,
		},
		redisBlackConf: RedisConf{
			addr:        redisBlackAddr,
			maxIdle:     redisBlackMaxIdle,
			maxActive:   redisBlackMaxActive,
			idleTimeOut: time.Duration(redisBlackIdleTimeout) * time.Second,
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
		CookieSecretKey:   cookieSecretKey,
		UserAccessLimit:   userAccessLimit,
		ReferWhitelist:    referWhiteList,
		UserIpAccessLimit: userIPAccessLimit,
		ReqChan:           make(chan *Req, 16), // todo 这个size可以配置化
	}
	logs.Info("配置信息: %+v", GFlashSellConf)
	return nil
}
func saveETCDConf() error {
	// save
	confs := map[int]ETCDProductInfo{
		1: {
			ProductId: 1,
			StartTime: time.Date(2025, 7, 10, 13, 0, 0, 0, time.Local),
			EndTime:   time.Date(2025, 7, 25, 13, 0, 0, 0, time.Local).Add(time.Hour),
			Status:    flash_sell.ProductNormal,
			Stock:     500,
		},
		2: {
			ProductId: 2,
			StartTime: time.Date(2025, 7, 25, 14, 0, 0, 0, time.Local),
			EndTime:   time.Date(2025, 7, 25, 14, 0, 0, 0, time.Local).Add(time.Hour),
			Status:    flash_sell.ProductNormal,
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
	key := fmt.Sprintf("%s/product", GFlashSellConf.etcdConf.key)
	_, err = etcdClient.Put(ctx, key, string(data))
	if err != nil {
		return fmt.Errorf("保存到etcd失败: %w", err)
	}
	logs.Info("保存秒杀配置成功, 商品ID0: %d, 路径: %s", confs[0].ProductId, key)
	return nil
}
func loadETCDConf() (err error) {
	key := fmt.Sprintf("%s/product", GFlashSellConf.etcdConf.key)
	resp, err := etcdClient.Get(context.Background(), key)
	if err != nil {
		logs.Error("get [%s] from etcd failed, err: %v", key, err)
		return err
	}
	for _, v := range resp.Kvs {
		logs.Debug("key: %s, value: %s", v.Key, v.Value)
	}
	// 反序列化为配置数组

	if err := json.Unmarshal(resp.Kvs[0].Value, &GFlashSellConf.EtcdProductInfos); err != nil {
		logs.Error("反序列化失败")
		return fmt.Errorf("解析配置失败: %w", err)
	}
	return nil
}
func watchETCDConf() error {
	key := fmt.Sprintf("%s/product", GFlashSellConf.etcdConf.key)
	logs.Info("开始监听配置变化: %s", key)

	rch := etcdClient.Watch(context.Background(), key)
	for resp := range rch {
		for _, ev := range resp.Events {
			switch ev.Type {
			case etcd.EventTypePut:
				logs.Info("检测到配置更新: %s", ev.Kv.Key)
				var newConfs = make(map[int]ETCDProductInfo)
				if err := json.Unmarshal(ev.Kv.Value, &newConfs); err != nil {
					logs.Error("解析新配置失败: %v", err)
					continue
				}
				//GFlashSellConf.lock.Lock()
				GFlashSellConf.EtcdProductInfos = newConfs
				//GFlashSellConf.lock.Unlock()
				logs.Info("配置更新成功! 新配置: %+v", newConfs)

			case etcd.EventTypeDelete:
				logs.Warn("配置被删除: %s", ev.Kv.Key)
				//GFlashSellConf.lock.Lock()
				GFlashSellConf.EtcdProductInfos = nil
				//GFlashSellConf.lock.Unlock()
				logs.Warn("已清空秒杀配置")
			}
		}
	}
	return nil
}

// 用Redis做队列
func initRedisQueue() {
	for i := 0; i < 16; i++ {
		// 从请求通道获取请求并写入写redis消息
		go func() {
			for req := range GFlashSellConf.ReqChan {
				conn := GFlashSellConf.redisPool.Get()
				data, err := json.Marshal(&req)
				if err != nil {
					logs.Error("json序列化失败, req: %v, err: %v", req, err)
					conn.Close()
					continue
				}
				_, err = conn.Do("LPUSH", "flash_sell_queue", data)
				if err != nil {
					logs.Error("redis LPUSH命令失败, data: %v, err: %v", data, err)
					conn.Close()
					continue
				}
				conn.Close()
			}
		}()
	}
	for i := 0; i < 16; i++ {
		// 从redis读取消息并做业务处理
		go func() {
			for {
				conn := GFlashSellConf.redisPool.Get()
				reply, err := redis.Values(conn.Do("BLPOP", "flash_sell_queue", 30*time.Second))
				if err != nil {
					if errors.Is(err, redis.ErrNil) {
						// 空队列是正常情况
						conn.Close()
						time.Sleep(100 * time.Millisecond)
						continue
					}
					logs.Error("Redis读取失败: %v", err)
					conn.Close()
					time.Sleep(time.Second)
					continue
				}
				// 解析BRPOP返回结果 [key, value]
				if len(reply) != 2 {
					logs.Warn("无效的队列响应: %v", reply)
					conn.Close()
					continue
				}
				data, ok := reply[1].([]byte)
				if !ok {
					logs.Error("无效的队列数据类型: %T", reply[1])
					conn.Close()
					continue
				}
				var req Req
				if err := json.Unmarshal(data, &req); err != nil {
					logs.Error("JSON解析失败: %v", err)
					conn.Close()
					continue
				}
				conn.Close()
				// todo 业务处理逻辑
			}
		}()
	}

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
	logs.Info("Redis地址: %s", GFlashSellConf.redisConf.addr)
	logs.Info("Etcd地址: %s", GFlashSellConf.etcdConf.addr)
	logs.Info("日志路径: %s", GFlashSellConf.logConf.path)
	logs.Info("日志级别: %s", GFlashSellConf.logConf.level)

	// 4.初始化redis
	if err := initRedis(); err != nil {
		return fmt.Errorf("初始化Redis失败: %w", err)
	}

	// 5. 初始化黑名单redis
	if err := initRedisBlack(); err != nil {
		return fmt.Errorf("初始化黑名单失败: %w", err)
	}

	// 6. 初始化Etcd
	if err := initEtcd(); err != nil {
		return fmt.Errorf("初始化Etcd失败: %w", err)
	}

	// 7. ETCD配置写入和读取
	if err = saveETCDConf(); err != nil {
		return fmt.Errorf("写入Etcd失败: %w", err)
	}
	if err := loadETCDConf(); err != nil {
		return fmt.Errorf("读取Etcd失败: %w", err)
	}

	// 8. 启动ETCD配置监听
	go watchETCDConf()

	// 9. 启动goroutine往redis里面写数据

	logs.Info("===== 所有组件初始化成功 =====")
	logs.Info("全局配置信息: %v", GFlashSellConf)
	return nil
}
