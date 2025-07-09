package flash_sell

import (
	"context"
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"github.com/gomodule/redigo/redis"
	etcd "go.etcd.io/etcd/client/v3"
	"log"
	"strconv"
	"strings"
	"time"
)

type FlashSellConf struct {
	redisConf RedisConf
	etcdConf  EtcdConf
}

type RedisConf struct {
	redisAddr        string
	redisMaxIdle     int
	redisMaxActive   int
	redisIdleTimeout time.Duration
}

type EtcdConf struct {
	etcdAddr string
}

var (
	gFlashSellConf *FlashSellConf
	pool           *redis.Pool
	etcdClient     *etcd.Client
)

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

func printClusterSummary(conn redis.Conn) {
	// 获取集群信息
	clusterInfo, err := redis.String(conn.Do("CLUSTER", "INFO"))
	if err != nil {
		log.Fatalf("获取集群信息失败: %v", err)
	}

	// 解析集群信息
	clusterStats := parseInfo(clusterInfo)
	fmt.Printf("模式: Redis集群\n")
	fmt.Printf("集群状态: %s\n", clusterStats["cluster_state"])
	fmt.Printf("节点数量: %s\n", clusterStats["cluster_known_nodes"])
	fmt.Printf("已分配槽位: %s/%s\n", clusterStats["cluster_slots_assigned"], "16384")

	// 获取内存信息
	memInfo, err := redis.String(conn.Do("INFO", "memory"))
	if err != nil {
		log.Fatalf("获取内存信息失败: %v", err)
	}
	memStats := parseInfo(memInfo)

	// 获取键数量
	keyspaceInfo, err := redis.String(conn.Do("INFO", "keyspace"))
	if err != nil {
		log.Fatalf("获取键空间信息失败: %v", err)
	}
	keyspaceStats := parseInfo(keyspaceInfo)

	// 获取当前节点配置
	configInfo, err := redis.Strings(conn.Do("CONFIG", "GET", "maxmemory-policy"))
	if err != nil || len(configInfo) < 2 {
		log.Printf("获取清除策略失败: %v", err)
	} else {
		fmt.Printf("清除策略: %s\n", configInfo[1])
	}

	// 打印容量信息
	printCapacityInfo(memStats, keyspaceStats)
}

func printStandaloneSummary(conn redis.Conn) {
	// 获取服务器信息
	info, err := redis.String(conn.Do("INFO"))
	if err != nil {
		log.Fatalf("获取Redis信息失败: %v", err)
	}
	infoStats := parseInfo(info)

	// 获取清除策略
	configInfo, err := redis.Strings(conn.Do("CONFIG", "GET", "maxmemory-policy"))
	if err != nil || len(configInfo) < 2 {
		log.Printf("获取清除策略失败: %v", err)
	} else {
		fmt.Printf("清除策略: %s\n", configInfo[1])
	}

	// 打印关键信息
	fmt.Printf("模式: 单节点\n")
	fmt.Printf("版本: %s\n", infoStats["redis_version"])
	fmt.Printf("运行时间: %s 天\n", infoStats["uptime_in_days"])

	// 打印容量信息
	printCapacityInfo(infoStats, infoStats)
}

func printCapacityInfo(memStats map[string]string, keyspaceStats map[string]string) {
	// 内存使用情况
	maxMemory, _ := strconv.ParseUint(memStats["maxmemory"], 10, 64)
	usedMemory, _ := strconv.ParseUint(memStats["used_memory"], 10, 64)

	fmt.Printf("\n===== 容量信息 =====\n")

	if maxMemory > 0 {
		memoryUsage := float64(usedMemory) / float64(maxMemory) * 100
		fmt.Printf("内存总量: %s\n", formatBytes(maxMemory))
		fmt.Printf("已用内存: %s (%.1f%%)\n", formatBytes(usedMemory), memoryUsage)
	} else {
		fmt.Printf("已用内存: %s\n", formatBytes(usedMemory))
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
	fmt.Printf("键总数: %d\n", totalKeys)

	// 内存碎片率
	fragRatio, _ := strconv.ParseFloat(memStats["mem_fragmentation_ratio"], 64)
	fmt.Printf("内存碎片率: %.2f\n", fragRatio)

	// 过期键信息
	if expiredKeys, ok := memStats["expired_keys"]; ok {
		fmt.Printf("已过期键: %s\n", expiredKeys)
	}
	if evictedKeys, ok := memStats["evicted_keys"]; ok {
		fmt.Printf("淘汰键数: %s\n", evictedKeys)
	}
}

func parseInfo(info string) map[string]string {
	stats := make(map[string]string)
	lines := strings.Split(info, "\r\n")

	for _, line := range lines {
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			stats[parts[0]] = parts[1]
		}
	}

	return stats
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func initRedis() error {
	pool = &redis.Pool{
		MaxIdle:     gFlashSellConf.redisConf.redisMaxIdle,
		MaxActive:   gFlashSellConf.redisConf.redisMaxActive,
		IdleTimeout: gFlashSellConf.redisConf.redisIdleTimeout,
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", "localhost:6379")
		},
	}
	conn := pool.Get()
	defer conn.Close()
	_, err := conn.Do("ping")
	if err != nil {
		logs.Error("ping redis failed, err:", err)
		return err
	}
	isCluster, err := isRedisCluster(conn)
	if err != nil {
		log.Fatalf("检测Redis模式失败: %v", err)
	}

	// 打印关键信息
	fmt.Println("===== Redis 关键信息 =====")
	if isCluster {
		printClusterSummary(conn)
	} else {
		printStandaloneSummary(conn)
	}

	return nil
}
func initEtcd() (err error) {
	config := etcd.Config{
		Endpoints:   []string{"localhost:2379"}, // etcd 节点地址
		DialTimeout: 5 * time.Second,            // 连接超时时间
		Username:    "root",                     // 用户名（如果启用认证）
		Password:    "secret",                   // 密码（如果启用认证）
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
func InitConfig() (err error) {
	redisAddr := beego.AppConfig.String("redis_addr")
	redisMaxIdle, _ := beego.AppConfig.Int("redis_max_idle")
	redisMaxActive, _ := beego.AppConfig.Int("redis_max_active")
	redisIdleTimeout, _ := beego.AppConfig.Int("redis_idle_timeout")
	etcdAddr := beego.AppConfig.String("etcd_addr")
	gFlashSellConf = &FlashSellConf{
		redisConf: RedisConf{
			redisAddr:        redisAddr,
			redisMaxIdle:     redisMaxIdle,
			redisMaxActive:   redisMaxActive,
			redisIdleTimeout: time.Duration(redisIdleTimeout) * time.Second,
		},
		etcdConf: EtcdConf{
			etcdAddr: etcdAddr,
		},
	}
	logs.Debug("config: %+v", gFlashSellConf)
	if len(redisAddr) == 0 || len(etcdAddr) == 0 {
		err = fmt.Errorf("redis addr or etcd addr empty", redisAddr, etcdAddr)
		return err
	}

	err = initRedis()
	if err != nil {
		logs.Error("init redis failed, err:", err)
		err = fmt.Errorf("init redis failed, err:%v", err)
		return err
	}

	err = initEtcd()
	if err != nil {
		logs.Error("init etcd failed, err:", err)
		err = fmt.Errorf("init etcd failed, err:%v", err)
		return err
	}
	logs.Info("init succeed")
	return nil
}
