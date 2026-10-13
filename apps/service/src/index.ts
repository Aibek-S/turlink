import express from 'express'
import type { Request, Response } from 'express'
import { main } from './serivce.ts';

const app = express()
const port = 3000

interface DetectBodyDto  {
  url: string;
  complicated?: boolean;
}



app.use(express.json())

app.get('/health', (req: Request, res: Response) => {
  res.json('ok')
})

app.post('/detect', async (req: Request<{}, {}, DetectBodyDto>, res: Response) => { //TODO CHECK WITH TESTS(FIX reputation.test.ts for the linter) and verify it is works with virusTotal
  const complicated = req.body.complicated
  if (!complicated) { // false and null
    const response = await main(req.body.url, "notComplicated")
    res.json(response)
    return
  }
  else {
    const response = await main(req.body.url, "complicated")
    res.json(response)
    return
  }

})

app.listen(3000, () => {
  console.log("Working on :3000 port")
})
