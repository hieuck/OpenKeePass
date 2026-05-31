public struct PasswordGeneratorOptions: Equatable, Sendable {
    public var length: Int
    public var includeUppercase: Bool
    public var includeLowercase: Bool
    public var includeDigits: Bool
    public var includeSymbols: Bool

    public init(
        length: Int,
        includeUppercase: Bool = true,
        includeLowercase: Bool = true,
        includeDigits: Bool = true,
        includeSymbols: Bool = false
    ) {
        self.length = length
        self.includeUppercase = includeUppercase
        self.includeLowercase = includeLowercase
        self.includeDigits = includeDigits
        self.includeSymbols = includeSymbols
    }
}

public enum PasswordGeneratorError: Error, Equatable, Sendable {
    case emptyCharacterSet
    case lengthTooShortForRequiredClasses
}

public struct PasswordGenerator: Sendable {
    public enum RandomSource: Sendable {
        case secure
        case deterministic(seed: UInt64)
    }

    private let random: RandomSource

    public init(random: RandomSource = .secure) {
        self.random = random
    }

    public func generate(options: PasswordGeneratorOptions) -> String {
        do {
            return try generateStrict(options: options)
        } catch {
            return ""
        }
    }

    public func generateStrict(options: PasswordGeneratorOptions) throws -> String {
        let enabledClasses = characterClasses(for: options)
        guard !enabledClasses.isEmpty else {
            throw PasswordGeneratorError.emptyCharacterSet
        }
        guard options.length >= enabledClasses.count else {
            throw PasswordGeneratorError.lengthTooShortForRequiredClasses
        }

        let allCharacters = enabledClasses.flatMap { $0 }
        var generator = RandomPicker(source: random)
        var password = enabledClasses.map { characterClass in
            characterClass[generator.nextIndex(upperBound: characterClass.count)]
        }

        while password.count < options.length {
            password.append(allCharacters[generator.nextIndex(upperBound: allCharacters.count)])
        }

        for index in password.indices.reversed() {
            let swapIndex = generator.nextIndex(upperBound: index + 1)
            password.swapAt(index, swapIndex)
        }

        return String(password)
    }

    private func characterClasses(for options: PasswordGeneratorOptions) -> [[Character]] {
        var classes: [[Character]] = []
        if options.includeUppercase {
            classes.append(Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
        }
        if options.includeLowercase {
            classes.append(Array("abcdefghijklmnopqrstuvwxyz"))
        }
        if options.includeDigits {
            classes.append(Array("0123456789"))
        }
        if options.includeSymbols {
            classes.append(Array("!@#$%^&*()-_=+[]{};:,.?/"))
        }
        return classes
    }
}

private struct RandomPicker {
    private var source: PasswordGenerator.RandomSource
    private var secureGenerator = SystemRandomNumberGenerator()
    private var deterministicState: UInt64

    init(source: PasswordGenerator.RandomSource) {
        self.source = source
        switch source {
        case .secure:
            deterministicState = 0
        case .deterministic(let seed):
            deterministicState = seed == 0 ? 0x9E3779B97F4A7C15 : seed
        }
    }

    mutating func nextIndex(upperBound: Int) -> Int {
        precondition(upperBound > 0, "upperBound must be positive")

        switch source {
        case .secure:
            return Int.random(in: 0..<upperBound, using: &secureGenerator)
        case .deterministic:
            deterministicState = deterministicState &* 6364136223846793005 &+ 1442695040888963407
            return Int(deterministicState % UInt64(upperBound))
        }
    }
}
