import { DurableObject } from 'cloudflare:workers';
import { controllerClass, gateway } from './controller.mjs';
export const SandprobeBox = controllerClass(DurableObject);
export default { fetch: gateway };
