declare module "cloudflare:workers" {
  interface ProvidedEnv extends Env {}
}

declare module "*?raw" {
  const value: string;
  export default value;
}
