package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/middleware-labs/synthetics-agent/pkg/worker"
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
				"timestamp": 1736406960108,
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
				"offsetX": 307,
				"offsetY": 5,
				"clickTime": "2025-01-09T07:16:00.106Z",
				"clickButton": 0
			},
			{
				"type": "click",
				"timestamp": 1736406966913,
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
				"offsetX": 225,
				"offsetY": 19,
				"clickTime": "2025-01-09T07:16:06.910Z",
				"clickButton": 0
			},
			{
				"type": "change",
				"timestamp": 1736406968536,
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
				"value": "hola"
			},
			{
				"type": "click",
				"timestamp": 1736406971547,
				"id": "",
				"className": "offcanvas-body",
				"tagName": "DIV",
				"selectors": [
					[
						"#navbar-default > div:nth-of-type(2)"
					],
					[
						"xpath///*[@id=\"navbar-default\"]/div[2]"
					],
					[
						"pierce/#navbar-default > div:nth-of-type(2)"
					],
					[
						"text/Pick LocationAll DepartmentsDairy, Bread & EggsSnacks & MunchiesFruits & VegetablesCold Drinks & JuicesBreakfast & Instant FoodBakery & BiscuitsChicken, Meat & FishAll DepartmentsDairy, Bread & EggsSnacks & MunchiesFruits & VegetablesCold Drinks & JuicesBreakfast & Instant FoodBakery & BiscuitsChicken, Meat & FishHomeHome 1Home 2Home 3Home 4Home 5ShopShop Grid - FilterShop Grid - 3 columnShop List - FilterShop - FilterShop WideShop SingleShop Single v2Shop WishlistShop CartShop CheckoutStoresStore ListStore GridStore SingleMega menuDairy, Bread & EggsButterMilk DrinksCurd & YogurtEggsBuns & BakeryCheeseCondensed MilkDairy ProductsBreakfast & Instant FoodBreakfast CerealNoodles, Pasta & SoupFrozen Veg SnacksFrozen Non-Veg SnacksVermicelliInstant MixesBatterFruit and JuicesCold Drinks & JuicesSoft DrinksFruit JuicesColdpressWater & Ice CubesSoda & MixersHealth DrinksHerbal DrinksMilk DrinksDont miss thisoffer today.Shop NowPagesBlogBlog SingleBlog CategoryAbout us404 ErrorContactAccountSign inSignupForgot PasswordMy AccountOrdersSettingsAddressPayment MethodNotificationDashboard"
					]
				],
				"offsetX": 1001,
				"offsetY": 7,
				"clickTime": "2025-01-09T07:16:11.544Z",
				"clickButton": 0
			},
			{
				"type": "click",
				"timestamp": 1736406976094,
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
				"offsetX": -413,
				"offsetY": 26,
				"clickTime": "2025-01-09T07:16:16.092Z",
				"clickButton": 0
			}
		]
	}`
	syntheticCheck := worker.SyntheticCheck{
		Uid: "synthetic-check-uid-123",
		SyntheticsModel: worker.SyntheticsModel{
			Id:              1,
			AccountId:       101,
			UserId:          202,
			Proto:           "https",
			SlugName:        "browser-test-example",
			Endpoint:        "https://example.com/test",
			IntervalSeconds: 300,
			Locations:       "us-east-1,eu-west-1",
			Status:          "active",
			Tags:            []string{"browser", "example", "test"},
			Request: worker.SyntheticsRequestOptions{
				TakeScreenshots: true,
				HTTPPayload:     worker.HTTPPayloadOptions{IgnoreServerCertificateError: true},
			},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
			Action:     "run",
			AccountKey: "account-key-123",
			AccountUID: "account-uid-456",
			Details: map[string]interface{}{
				"test_type":   "browser",
				"description": "Synthetic browser test for example.com",
			},
			CheckTestRequest: worker.CheckTestRequest{
				URL: "https://example.com",
				Headers: map[string]string{
					"User-Agent": "Synthetic-Browser-Test-Agent",
				},
				Browsers: map[string][]string{
					// "chrome":  {"laptop", "mobile", "tablet"},
					// "firefox": {"laptop"},
					"edge": {"laptop"},
				},
				Recording:  json.RawMessage(recordingData),
				StepsCount: 10,
				Timeout:    7000,
			},
		},
	}
	browserChecker := worker.NewBrowserChecker(syntheticCheck)
	browsers := syntheticCheck.CheckTestRequest.Browsers
	var wg sync.WaitGroup

	for browser, devices := range browsers {
		wg.Add(1)
		go func(browser string) {
			defer wg.Done()
			for _, device := range devices {
				commandArgs := worker.CommandArgs{
					Browser:    browser,
					CollectRum: true,
					Device:     device,
					Region:     syntheticCheck.Locations,
					TestId:     fmt.Sprintf("%s-%s-%s", string(syntheticCheck.Uid), "india", "hash"),
				}
				browserChecker.CmdArgs = commandArgs
				_ = browserChecker.Check()
				// cs.finishCheckRequest(testStatus, browserChecker.getTimers(), browserChecker.getAttrs())
			}
		}(browser)
	}

	wg.Wait()
}
