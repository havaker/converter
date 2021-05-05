# Budowanie

* `apt install cargo g++ cmake python3`
* `cargo build --release`

Plik wykonywalny będzie w `target/release/converter`

# Rozwiązanie

Postanowiłem napisać konwerter w języku Rust.
Jedyną w miarę sensowną biblioteką do obsługi ELF, którą znalazłem był `goblin`.
Udostępnia on interfejs, za pomocą którego można łatwo czytać zawartość ELF, ale niestety nie da się ich już tak łatwo modyfikować (być może wcale się nie da).
Pracę nad zadaniem zacząłem więc od implementacji własnych struktur (korzystających wewnętrznie z `goblin`), które pozwalałyby mi na wczytywanie, modyfikacje i zapis plików ELF.
W taki sposób powstał moduł `rel` (folder `src/rel`).

Mając już sposób na modyfikację ELFów zacząłem się zastanawiać nad sposobem generowania stubów. Zauważyłem, że w przykładowym stubie wywołującym 32-bitową funkcję z 64-bitowego kodu można wyróżnić 3 fragmenty.

1. zapisywanie rejestrów, translacja argumentów
2. zmiana trybu na 32-bitowy, wywołanie właściwej funkcji i powrót do 64-bitów
3. konwersja zwracanej wartości i odtwarzanie rejestrów

Pierwszy i trzeci fragment są zależne od sygnatury funkcji, ale nie mają żadnych relokacji.
Drugi fragment jest niezależny od sygnatury i ma relokacje.

Aby uniknąć ręcznego generowania symboli i relokacji, postanowiłem wygenerować obiektowy plik ELF, mający w sekcji `.text` kod drugiego fragmentu opisywanego wyżej stuba (a w innych sekcjach niezbędne symbole i relokacje).
Użyłem do tego `GNU AS` (`as call32from64.a -o call32from64.o`) i powstały plik zapisałem w `assets/call32from64.o`.
Jest on wbudowywany w konwerter podczas kompilacji.

Aby stworzyć stub dla pewnej funkcji (zdefiniowanej w konwertowanym pliku), konwerter tworzy obiekt reprezentujący plik ELF opisany powyżej (`call32from64.o`) a następnie dokleja do niego wygenerowany dynamicznie pierwszy i trzeci fragment. Do tego wszystkiego służy moduł `gen` (folder `src/gen`).

Moduł `gen` dzieli się na 3 podmoduły:

* `func` - parsowanie sygnatur funkcji i generowanie assemblera do
  + zapisywania rejestrów
  + translacji argumentów
  + konwersji zwracanej wartości
  + odtwarzania rejestrów
* `thunk` - generowanie obiektów `Thunk`, które
  + tworzy się przy użyciu szablonu (jakim jest plik ELF z relokacjami)
  + pozwalają na doklejanie wygenerowanego kodu na początek/koniec sekcji `.text` (i odpowiednio aktualizują relokacje/symbole)
* `generator` - generowanie sekcji grupujących stuby (które reprezentowane są przez `Thunk`) i scalanie ich z przetwarzanym plikiem, generowanie kodu maszynowego (za pomocą biblioteki `keystone`) z assemblera wygenerowanego przez `func`.

Finalnie konwerter produkuje plik z nowymi sekcjami:

* `.text.thunkin`
* `.rodata.thunkin`
* `.text.thunkout`
* `.rodata.thunkout`
* `.rela.text.thunkin`
* `.rela.rodata.thunkin`
* `.rela.text.thunkout`
* `.rela.rodata.thunkout`

W których przechowywane są wygenerowane stuby.
