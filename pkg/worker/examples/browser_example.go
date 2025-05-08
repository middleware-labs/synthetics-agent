package main

import (
	"fmt"
	"sync"
)

func main() {
	recordingData := `
	{
		"title": "Recording 01/01/2025 at 19:04:54",
		"steps": [
			{
				"type": "setViewport",
				"width": 1444,
				"height": 1080,
				"deviceScaleFactor": 1,
				"isMobile": false,
				"hasTouch": false,
				"isLandscape": false
			},
			{
				"type": "navigate",
				"url": "https://demo2.mw.dev/",
				"assertedEvents": [
					{
						"type": "navigation",
						"url": "https://demo2.mw.dev/",
						"title": ""
					}
				]
			},
			{
				"type": "click",
				"timestamp": 1736418041012,
				"id": "",
				"className": "mb-0",
				"tagName": "H3",
				"selectors": [
					[
						"#root > main > section > div > div > div > h3"
					],
					[
						"xpath///*[@id=\"root\"]/main/section/div/div/div/h3"
					],
					[
						"pierce/#root > main > section > div > div > div > h3"
					],
					[
						"text/Products"
					]
				],
				"offsetX": 509,
				"offsetY": 18,
				"clickTime": "2025-01-09T10:20:41.010Z",
				"clickButton": 0
			},
			{
				"type": "click",
				"timestamp": 1736418043790,
				"id": "",
				"className": "{}",
				"tagName": "svg",
				"selectors": [
					[
						"#root > main > section > div > div:nth-of-type(2) > div > div > div > div > div:nth-of-type(4) > div:nth-of-type(2) > button > svg"
					],
					[
						"xpath///*[@id=\"root\"]/main/section/div/div[2]/div/div/div/div/div[4]/div[2]/button/svg"
					],
					[
						"pierce/#root > main > section > div > div:nth-of-type(2) > div > div > div > div > div:nth-of-type(4) > div:nth-of-type(2) > button > svg"
					]
				],
				"offsetX": 11,
				"offsetY": 11,
				"clickTime": "2025-01-09T10:20:43.788Z",
				"clickButton": 0
			},
			{
				"type": "click",
				"timestamp": 1736418046320,
				"id": "",
				"className": "form-control rounded",
				"tagName": "INPUT",
				"selectors": [
					[
						"#root > div > div:nth-of-type(2) > div > div > div:nth-of-type(2) > form > div > input"
					],
					[
						"xpath///*[@id=\"root\"]/div/div[2]/div/div/div[2]/form/div/input"
					],
					[
						"pierce/#root > div > div:nth-of-type(2) > div > div > div:nth-of-type(2) > form > div > input"
					]
				],
				"offsetX": 262,
				"offsetY": 15,
				"clickTime": "2025-01-09T10:20:46.318Z",
				"clickButton": 0
			},
			{
				"type": "change",
				"timestamp": 1736418050874,
				"id": "",
				"className": "form-control rounded",
				"tagName": "INPUT",
				"selectors": [
					[
						"#root > div > div:nth-of-type(2) > div > div > div:nth-of-type(2) > form > div > input"
					],
					[
						"xpath///*[@id=\"root\"]/div/div[2]/div/div/div[2]/form/div/input"
					],
					[
						"pierce/#root > div > div:nth-of-type(2) > div > div > div:nth-of-type(2) > form > div > input"
					]
				],
				"value": "hey there!!!"
			},
			{
				"type": "click",
				"timestamp": 1736418051254,
				"id": "",
				"className": "navbar navbar-expand-lg navbar-light navbar-default py-0 pb-lg-4",
				"tagName": "NAV",
				"selectors": [
					[
						"aria/Offcanvas navbar large"
					],
					[
						"#root > div > nav"
					],
					[
						"xpath///*[@id=\"root\"]/div/nav"
					],
					[
						"pierce/#root > div > nav"
					],
					[
						"text/Pick LocationAll DepartmentsDairy, Bread & EggsSnacks & MunchiesFruits & VegetablesCold Drinks & JuicesBreakfast & Instant FoodBakery & BiscuitsChicken, Meat & FishAll DepartmentsDairy, Bread & EggsSnacks & MunchiesFruits & VegetablesCold Drinks & JuicesBreakfast & Instant FoodBakery & BiscuitsChicken, Meat & FishHomeHome 1Home 2Home 3Home 4Home 5ShopShop Grid - FilterShop Grid - 3 columnShop List - FilterShop - FilterShop WideShop SingleShop Single v2Shop WishlistShop CartShop CheckoutStoresStore ListStore GridStore SingleMega menuDairy, Bread & EggsButterMilk DrinksCurd & YogurtEggsBuns & BakeryCheeseCondensed MilkDairy ProductsBreakfast & Instant FoodBreakfast CerealNoodles, Pasta & SoupFrozen Veg SnacksFrozen Non-Veg SnacksVermicelliInstant MixesBatterFruit and JuicesCold Drinks & JuicesSoft DrinksFruit JuicesColdpressWater & Ice CubesSoda & MixersHealth DrinksHerbal DrinksMilk DrinksDont miss thisoffer today.Shop NowPagesBlogBlog SingleBlog CategoryAbout us404 ErrorContactAccountSign inSignupForgot PasswordMy AccountOrdersSettingsAddressPayment MethodNotificationDashboard"
					]
				],
				"offsetX": 880,
				"offsetY": 49,
				"clickTime": "2025-01-09T10:20:51.251Z",
				"clickButton": 0
			},
			{
				"type": "click",
				"timestamp": 1736418054439,
				"id": "",
				"className": "{}",
				"tagName": "svg",
				"selectors": [
					[
						"#root > div > div:nth-of-type(2) > div > div > div:nth-of-type(4) > div > div:nth-of-type(3) > a > svg"
					],
					[
						"xpath///*[@id=\"root\"]/div/div[2]/div/div/div[4]/div/div[3]/a/svg"
					],
					[
						"pierce/#root > div > div:nth-of-type(2) > div > div > div:nth-of-type(4) > div > div:nth-of-type(3) > a > svg"
					]
				],
				"offsetX": 1,
				"offsetY": 11,
				"clickTime": "2025-01-09T10:20:54.435Z",
				"clickButton": 0
			},
			{
				"type": "click",
				"timestamp": 1736418057376,
				"id": "",
				"className": "btn btn-primary",
				"tagName": "BUTTON",
				"selectors": [
					[
						"#offcanvasRight > div:nth-of-type(2) > div > div > button:nth-of-type(2)"
					],
					[
						"xpath///*[@id=\"offcanvasRight\"]/div[2]/div/div/button[2]"
					],
					[
						"pierce/#offcanvasRight > div:nth-of-type(2) > div > div > button:nth-of-type(2)"
					],
					[
						"text/Checkout"
					]
				],
				"offsetX": -340,
				"offsetY": 25,
				"clickTime": "2025-01-09T10:20:57.374Z",
				"clickButton": 0
			}
		]
	}`
	// syntheticCheck := worker.SyntheticCheck{
	// 	Uid: "synthetic-check-uid-123",
	// 	SyntheticsModel: worker.SyntheticsModel{
	// 		Id:              1,
	// 		AccountId:       101,
	// 		UserId:          202,
	// 		Proto:           "https",
	// 		SlugName:        "browser-test-example",
	// 		Endpoint:        "https://example.com/test",
	// 		IntervalSeconds: 300,
	// 		Locations:       "us-east-1,eu-west-1",
	// 		Status:          "active",
	// 		Tags:            []string{"browser", "example", "test"},
	// 		Request: worker.SyntheticsRequestOptions{
	// 			TakeScreenshots: true,
	// 			HTTPPayload:     worker.HTTPPayloadOptions{IgnoreServerCertificateError: true},
	// 		},
	// 		CreatedAt:  time.Now(),
	// 		UpdatedAt:  time.Now(),
	// 		Action:     "run",
	// 		AccountKey: "account-key-123",
	// 		AccountUID: "account-uid-456",
	// 		Details: map[string]interface{}{
	// 			"test_type":   "browser",
	// 			"description": "Synthetic browser test for example.com",
	// 		},
	// 		// CheckTestRequest: worker.CheckTestRequest{
	// 		// 	URL: "https://example.com",
	// 		// 	Headers: map[string]string{
	// 		// 		"User-Agent": "Synthetic-Browser-Test-Agent",
	// 		// 	},
	// 		// 	Browsers: map[string][]string{
	// 		// 		"chrome": {"laptop", "mobile", "tablet"},
	// 		// 		// "firefox": {"laptop"},
	// 		// 		// "edge": {"laptop"},
	// 		// 	},
	// 		// 	Recording:  json.RawMessage(recordingData),
	// 		// 	StepsCount: 10,
	// 		// 	Timeout:    7000,
	// 		// },
	// 	},
	// }
	// browserChecker := worker.NewBrowserChecker(syntheticCheck)
	// browsers := syntheticCheck.CheckTestRequest.Browsers
	var wg sync.WaitGroup

	// for browser, devices := range browsers {
	// 	wg.Add(1)
	// 	go func(browser string) {
	// 		defer wg.Done()
	// 		for _, device := range devices {
	// 			commandArgs := worker.CommandArgs{
	// 				Browser:    browser,
	// 				CollectRum: true,
	// 				Device:     device,
	// 				Region:     syntheticCheck.Locations,
	// 				TestId:     fmt.Sprintf("%s-%s-%s", string(syntheticCheck.Uid), "india", "hash"),
	// 			}
	// 			browserChecker.CmdArgs = commandArgs
	// 			_ = browserChecker.Check()
	// 			// cs.finishCheckRequest(testStatus, browserChecker.getTimers(), browserChecker.getAttrs())
	// 		}
	// 	}(browser)
	// }

	fmt.Printf("recordingData: %+v", recordingData)
	wg.Wait()
}
