// The chat helper calls OpenAI straight from the browser, so its key had to be a VITE_ variable,
// and Vite bakes every VITE_ variable into the bundle every visitor downloads.
import OpenAI from "openai";
const openai = new OpenAI({ apiKey: import.meta.env.VITE_OPENAI_API_KEY, dangerouslyAllowBrowser: true });
export async function ask(q) {
  const r = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: q }] });
  return r.choices[0].message.content;
}
