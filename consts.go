package flash_sell

const (
	Succeed      = 0
	InvalidParms = 100
	ServiceError = 500
)

type ProductStatus int

const (
	ProductNormal       = 0 // 商品正常售卖
	ProductSoldOut      = 1 // 商品已经售光
	ProductForceSoldOut = 2 // 强制商品已经售卖光
)
