import 'dart:convert';

import 'package:flutter/material.dart';

import 'auth.dart';

class KenniApp extends StatelessWidget {
  const KenniApp({super.key, required this.controller});

  final AuthController controller;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Kenni — Flutter example',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xFFF4F5F7),
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1F2933),
          brightness: Brightness.light,
        ),
      ),
      home: ListenableBuilder(
        listenable: controller,
        builder: (context, _) => _Home(controller: controller),
      ),
    );
  }
}

class _Home extends StatelessWidget {
  const _Home({required this.controller});

  final AuthController controller;

  String _heading() {
    if (!controller.isAuthenticated) return 'Kenni — Flutter example';
    final name = controller.displayName;
    return name != null ? 'Welcome $name' : 'Welcome';
  }

  @override
  Widget build(BuildContext context) {
    if (!controller.isReady) {
      return const Scaffold(
        body: SafeArea(
          child: Center(child: Text('Loading…', style: TextStyle(fontSize: 22))),
        ),
      );
    }

    return Scaffold(
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                _heading(),
                textAlign: TextAlign.center,
                style: const TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.w700,
                  color: Color(0xFF1F2933),
                ),
              ),
              const SizedBox(height: 24),
              if (controller.error != null) _ErrorBanner(message: controller.error!),
              _ButtonStack(controller: controller),
              if (controller.isAuthenticated && controller.profile != null) ...[
                const SizedBox(height: 24),
                _JsonPanel(value: controller.profile!),
              ],
            ],
          ),
        ),
      ),
    );
  }
}

class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner({required this.message});
  final String message;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFFFDE2E2),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Text(
        message,
        style: const TextStyle(
          color: Color(0xFF7A1E1E),
          fontFamily: 'Courier',
          fontSize: 12,
        ),
      ),
    );
  }
}

class _ButtonStack extends StatelessWidget {
  const _ButtonStack({required this.controller});

  final AuthController controller;

  @override
  Widget build(BuildContext context) {
    final signedIn = controller.isAuthenticated;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (!signedIn)
          _PrimaryButton(
            label: 'Continue with Kenni',
            onPressed: controller.isLoading ? null : () => controller.signIn(),
          ),
        if (signedIn) ...[
          _PrimaryButton(
            label: controller.supportsRpInitiatedLogout
                ? 'Sign out (local)'
                : 'Sign out',
            onPressed: () => controller.signOutLocal(),
          ),
          if (controller.supportsRpInitiatedLogout) ...[
            const SizedBox(height: 12),
            _PrimaryButton(
              label: 'RP-initiated logout',
              onPressed: () => controller.signOutRemote(),
            ),
          ],
        ],
      ],
    );
  }
}

class _PrimaryButton extends StatelessWidget {
  const _PrimaryButton({required this.label, required this.onPressed});

  final String label;
  final VoidCallback? onPressed;

  @override
  Widget build(BuildContext context) {
    return ElevatedButton(
      onPressed: onPressed,
      style: ElevatedButton.styleFrom(
        backgroundColor: const Color(0xFF1F2933),
        foregroundColor: Colors.white,
        disabledBackgroundColor: const Color(0xFF1F2933).withValues(alpha: 0.5),
        disabledForegroundColor: Colors.white.withValues(alpha: 0.7),
        padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 18),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
        ),
        textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
      ),
      child: Text(label),
    );
  }
}

class _JsonPanel extends StatelessWidget {
  const _JsonPanel({required this.value});

  final Map<String, dynamic> value;

  @override
  Widget build(BuildContext context) {
    final formatted = const JsonEncoder.withIndent('  ').convert(value);
    return ConstrainedBox(
      constraints: const BoxConstraints(maxHeight: 400),
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: const Color(0xFF0B1117),
          borderRadius: BorderRadius.circular(10),
        ),
        child: SingleChildScrollView(
          child: SelectableText(
            formatted,
            style: const TextStyle(
              color: Color(0xFFD1D5DB),
              fontFamily: 'Courier',
              fontSize: 12,
              height: 1.5,
            ),
          ),
        ),
      ),
    );
  }
}
