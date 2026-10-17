import express from 'express'
import type { Request, Response } from 'express'
import { main } from './serivce.ts';
import type { DetectBodyDto } from './types.ts';
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

// TODO: put away all business logics in this endpoint. and change main() method's name
app.post('/detect', async (req: Request<{}, {}, DetectBodyDto>, res: Response) => {
  const complicated = req.body.complicated
  if (!complicated) { // false and null
    const response = await main(req.body.url, "notComplicated")
    res.json(response)
  }
  else {
    const response = await main(req.body.url, "complicated")
    res.json(response)
  }
})

app.listen(3000, () => {
  console.log("Working on :3000 port")
})
