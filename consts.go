package flash_sell

const (
	Succeed         = 0
	InvalidParms    = 100
	InvalidUser     = 200
	UserFreqControl = 201
	ServiceError    = 500
	EventNotStart   = 600
	EventEnd        = 601
)

type ProductStatus int

const (
	ProductNormal       = 0 // 商品正常售卖
	ProductSoldOut      = 1 // 商品已经售光
	ProductForceSoldOut = 2 // 强制商品已经售卖光
)

func (p ProductStatus) String() string {
	switch p {
	case ProductNormal:
		return "ProductNormal"
	case ProductSoldOut:
		return "ProductSoldOut"
	case ProductForceSoldOut:
		return "ProductForceSoldOut"
	default:
		return "ProductInvalid"
	}
}
