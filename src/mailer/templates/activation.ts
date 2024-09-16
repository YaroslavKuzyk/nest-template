import Slot from './Slot';

export default function(url: string, name: string) {
  return(
    Slot(`
      <h1>Hi ${name}!</h1>
      <p>Click the link below to activate your account</p>
      <a href="${url}">Activate</a>
    `)
  )
}