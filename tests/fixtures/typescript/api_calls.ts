import axios from "axios";

// fetch calls
const users = await fetch("/api/users");
const detail = await fetch(`/api/users/${id}`);

// axios calls
const posts = await axios.get("/api/posts");
const created = await axios.post("/api/posts", { title: "New" });
const updated = await axios.put(`/api/posts/${id}`, { title: "Updated" });
const deleted = await axios.delete(`/api/posts/${id}`);
