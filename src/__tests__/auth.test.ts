import axios from "axios";
import { describe, it, expect } from "vitest";

const BASE_URL = "http://localhost:8080";

describe("Auth API Tests", () => {

  it("Signup user", async () => {
    const res = await axios.post(`${BASE_URL}/api/auth/signup`, {
      email: "givemeintershipbroplease@gmail.com",
      password: "",
      username: BigInt,
    });
    console.log(res.data)
    expect(res.status).toBe(200);
  });

  it("valid login", async () => {
    const res = await axios.post(`${BASE_URL}/api/auth/signin`, {
      username: BigInt,
      password: ""
    });
        console.log(res.data)

    expect(res.status).toBe(200);
  });

});

it("Missing required fields", async () => {
  try {
    await axios.post(`${BASE_URL}/api/auth/signin`, {});
  } catch (err: any) {
    console.log(err.response?.status);
  }
});

it("User enumeration vulnerability", async () => {
  let status1 = null;
  let status2 = null;

  try {
    await axios.post(`${BASE_URL}/api/auth/signin`, {
      username: "nonexistent_user",
      password: "1234"
    });
  } catch (err: any) {
    status1 = err.response?.status;
  }

  try {
    await axios.post(`${BASE_URL}/api/auth/signin`, {
      username: "newbee",
      password: "wrongpassword"
    });
  } catch (err: any) {
    status2 = err.response?.status;
  }

  console.log("status1:", status1);
  console.log("status2:", status2);

  expect(status1).toBeDefined();
  expect(status2).toBeDefined();
  expect(status1).not.toBe(status2);
});


it("MongoDB injection attempt on login", async () => {
  try {
    const res = await axios.post(`${BASE_URL}/api/auth/signin`, {
      username: { "$ne": null },
      password: "anything"
    });

    console.log("Response:", res.data);

    // If login succeeds → vulnerability
    expect(res.status).not.toBe(200);
  } catch (err: any) {
    console.log("Blocked with status:", err.response?.status);
    expect(err.response.status).toBeGreaterThanOrEqual(400);
  }
});


it("Mongo injection: $gt operator", async () => {
  try {
    await axios.post(`${BASE_URL}/api/auth/signin`, {
      username: { $gt: "" },
      password: "anything"
    });
  } catch (err: any) {
    console.log("Status:", err.response?.status);
  }
});


it("Mongo injection: regex match", async () => {
  try {
    await axios.post(`${BASE_URL}/api/auth/signin`, {
      username: { $regex: ".*" },
      password: "anything"
    });
  } catch (err: any) {
    console.log("Status:", err.response?.status);
  }
});


it("Mongo injection: nested operator", async () => {
  try {
    await axios.post(`${BASE_URL}/api/auth/signin`, {
      username: { $ne: "invalid_user" },
      password: "anything"
    });
  } catch (err: any) {
    console.log("Status:", err.response?.status);
  }
});


it("Mongo injection: type confusion", async () => {
  try {
    await axios.post(`${BASE_URL}/api/auth/signin`, {
      username: { $in: ["newbee", "admin"] },
      password: "anything"
    });
  } catch (err: any) {
    console.log("Status:", err.response?.status);
  }
}); 



it("Mongo injection: malformed payload", async () => {
  try {
    await axios.post(`${BASE_URL}/api/auth/signin`, {
      username: { $ne: null, $gt: "" },
      password: { $ne: null }
    });
  } catch (err: any) {
    console.log("Status:", err.response?.status);
  }
});