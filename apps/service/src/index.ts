import express from 'express'
import type { Request, Response } from 'express'
import { inspection } from './serivce.ts';
import type { DetectBodyDto, DetectionType } from './types.ts';
import { checkVirusTotalKey } from './reputation.ts';

const app = express()
const port = 3000

app.use(express.json())

app.get('/health', (req: Request, res: Response) => {   
  res.json('ok')
}) 

app.get("/detect/check", async (req: Request, res: Response) => {
  res.json(await checkVirusTotalKey(req.get("x-apikey")))
})


app.post('/detect', async (req: Request<{}, {}, DetectBodyDto>, res: Response) => {
  const complicated: DetectionType = req.body.complicated
  const response = await inspection(req.body.url, complicated, req.get("x-apikey"))
  res.json(response)
})

app.listen(3000, () => {
  console.log("Working on :3000 port")
})
