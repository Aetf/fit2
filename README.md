# serverless AWS Rust with routing

 with routing support.

Serverless [Rustlang AWS Lambda](https://github.com/awslabs/aws-lambda-rust-runtime/) applications with ⚡ serverless framework ⚡
with [routing](https://github.com/routerify/routerify).

## ✨ features

* 🦀 Build Rustlang applications with ease
- 🛵 Continuous integration testing with GitHub Actions
- 🚀 Continuous deployment with GitHub Actions
* 🧪 Getting started unit tests

## 🛵 continuous integration and deployment

Store a `AWS_ACCESS_KEY_ID` `AWS_SECRET_ACCESS_KEY` used for aws deployment in your repositories [secrets](https://github.com/Aetf/fit2/settings/secrets).

## 🔫 function triggering

With your function deployed you can now start triggering it using `serverless` framework directly or
the AWS integration you've configured to trigger it on your behalf

```sh
$ npx serverless invoke -f hello -d '{"foo":"bar"}'
```

## 🔬 logs

With your function deployed you can now tail it's logs right from your project

```sh
$ npx serverless logs -f hello
```

```sh
$ npx serverless logs -f world
```

## 👴 retiring

Good code should be easily replaceable. Good code is should also be easily disposable. Retiring applications should be as easy as creating and deploying them them. The dual of `serverless deploy` is `serverless remove`. Use this for retiring services and cleaning up resources.

```sh
$ npx serverless remove
```

## ℹ️  additional information

* See the [serverless-rust plugin's documentation](https://github.com/softprops/serverless-rust) for more information on plugin usage.

* See the [aws rust runtime's documentation](https://github.com/awslabs/aws-lambda-rust-runtime) for more information on writing Rustlang lambda functions
