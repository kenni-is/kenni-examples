import 'package:flutter/material.dart';

import 'src/app.dart';
import 'src/auth.dart';
import 'src/config.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final config = KenniConfig.fromEnvironment();
  final controller = AuthController(config);
  await controller.load();

  runApp(KenniApp(controller: controller));
}
