package flash_sell

import (
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"github.com/gomodule/redigo/redis"
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
)

func initRedis() error {
	pool = &redis.Pool{
		MaxIdle:     gFlashSellConf.redisConf.redisMaxIdle,
		MaxActive:   gFlashSellConf.redisConf.redisMaxActive,
		IdleTimeout: gFlashSellConf.redisConf.redisIdleTimeout,
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", "localhost:6379")
		},
	}
	return nil
}

func initEtcd() error {
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
