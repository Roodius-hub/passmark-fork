import axios from "axios";
import { describe, it, expect } from "vitest";

const BASE_URL = "http://localhost:8080";


it("Access with invalid JWT token", async () => {
  try {
    const res = await axios.get(`${BASE_URL}/api/test/user`, {
      headers: {
        "x-access-token": "invalid.token.here"
      }
    });
    console.log(res.data)
  } catch (err: any) {
    console.log("Status:", err.response.status);
    expect(err.response.status).toBe(401);
  }
});

it("Access without JWT token", async () => {
  try {
    const res= await axios.get(`${BASE_URL}/api/test/user`);
    console.log(res.data)
  } catch (err: any) {
    expect(err.response.status).toBe(401);
  }
});


it("JWT tampering attack", async () => {
  const validToken = "PASTE_YOUR_REAL_TOKEN_HERE";

  const tamperedToken = validToken.slice(0, -5) + "abcde";

  try {
    await axios.get(`${BASE_URL}/api/test/user`, {
      headers: {
        "x-access-token": tamperedToken
      }
    });
  } catch (err: any) {
    console.log("Tampered token blocked:", err.response.status);
    expect(err.response.status).toBe(401);
  }
});


it("JWT payload manipulation", async () => {
  const fakeToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.payload";

  try {
    await axios.get(`${BASE_URL}/api/test/user`, {
      headers: {
        "x-access-token": fakeToken
      }
    });
  } catch (err: any) {
    expect(err.response.status).toBe(401);
  }
});