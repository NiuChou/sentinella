// Named imports
import { useState, useEffect } from "react";
import { Router } from "express";

// Default import
import axios from "axios";

// Namespace import
import * as path from "path";

// Type-only import
import type { Request, Response } from "express";

// Side-effect import
import "./styles.css";

// Re-export
export { useState } from "react";

// Dynamic import (template literal)
const mod = await import(`./modules/${name}`);
