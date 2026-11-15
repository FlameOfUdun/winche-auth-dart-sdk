import 'package:winche_auth/winche_auth.dart';
import 'package:winche_core/winche_core.dart';

/// Against a local emulator: `winche emulators start`, then `dart run example/main.dart`.
Future<void> main() async {
  Winche.initializeApp(options: WincheOptions.emulator());
  final auth = WincheAuth.instance;
  auth.authStateChanges().listen((user) => print(user == null ? 'signed out' : 'signed in as ${user.uid}'));

  final user = await auth.signInAnonymously();
  print('guest ${user.uid}, token claims: ${await auth.getTokenClaims()}');
  await auth.signOut();
  await Winche.deinitializeAll();
}
