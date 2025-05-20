/**
 * @copyright 2025 Miller Zhang
 * @author Miller Zhang
 * @license Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * {@link http://www.apache.org/licenses/LICENSE-2.0}
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

/**
 * @class RandomUtils
 * @description A utility class for generating random numbers and characters.
 * It attempts to use cryptographically secure random number generation if available,
 * otherwise falls back to Math.random().
 */
class RandomUtils {
    // essentials for the random base

    /**
     * @static
     * @private
     * @constant
     * @type {number}
     * @description Maximum value for an unsigned 32-bit integer.
     */
    static #UINT32_MAX = 0xFFFFFFFF;

    /**
     * @static
     * @private
     * @constant
     * @type {number}
     * @description Range size of letters (a-z).
     */
    static #LETTER_RANGE_SIZE = 26;

    /**
     * @static
     * @private
     * @constant
     * @type {number}
     * @description Range size of digits (0-9).
     */
    static #DIGIT_RANGE_SIZE = 10;

    /**
     * @static
     * @private
     * @type {boolean}
     * @description Flag indicating if the Web Crypto API is available.
     */
    static #isCryptoAvailable = !!(typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues);

    /**
     * @static
     * @private
     * @type {Uint32Array}
     * @description Buffer for storing random values from the Web Crypto API.
     */
    static #buffer = new Uint32Array(1);

    /**
     * @static
     * @private
     * @function
     * @returns {number} A 32-bit random integer generated using window.crypto.
     * @description Generates a random 32-bit unsigned integer using the Web Crypto API.
     */
    static #baseOnCrypto = () => {
        let randomVal;
        window.crypto.getRandomValues(this.#buffer);
        randomVal = this.#buffer[0];
        return randomVal;
    }

    /**
     * @static
     * @private
     * @function
     * @returns {number} A 32-bit random integer generated using Math.random().
     * @description Generates a random 32-bit unsigned integer using Math.random().
     * This is a fallback if Web Crypto API is not available.
     */
    static #baseOnMath = () => Math.floor(Math.random() * (this.#UINT32_MAX + 1));

    /**
     * @static
     * @private
     * @function
     * @returns {number} A 32-bit random integer from the selected base generator.
     * @description Selects the appropriate base random number generator (crypto or math).
     */
    static #base = this.#isCryptoAvailable ? this.#baseOnCrypto : this.#baseOnMath;

    /**
     * @static
     * @public
     * @function
     * @returns {number} A 32-bit unsigned random integer.
     * @description Provides a base 32-bit unsigned random integer.
     * It uses cryptographically secure generation if available, otherwise Math.random().
     */
    static randomBase = () => this.#base();

    /**
     * @static
     * @private
     * @type {number}
     * @description The upper exclusive bound for the randomInt() method.
     * Default is 0x7FFF (32767), meaning randomInt() will generate numbers from 0 to 32766.
     */
    static #randomIntRange = 0x7FFF;    // C-style random range

    /**
     * @static
     * @private
     * @function
     * @returns {number} The largest multiple of #randomIntRange that is less than or equal to #UINT32_MAX + 1.
     * @description Calculates the maximum valid value for the base random number before modulo,
     * to ensure an unbiased distribution for randomInt().
     */
    static #RandomIntUnbiasedRange = () => Math.floor((this.#UINT32_MAX + 1) / this.#randomIntRange) * this.#randomIntRange;

    /**
     * @static
     * @private
     * @function
     * @returns {number} The largest multiple of #LETTER_MAX that is less than or equal to #UINT32_MAX + 1.
     * @description Calculates the maximum valid value for the base random number before modulo,
     * to ensure an unbiased distribution for randomLetter().
     */
    static #RandomLetterUnbiasedRange = () => Math.floor((this.#UINT32_MAX + 1) / this.#LETTER_RANGE_SIZE) * this.#LETTER_RANGE_SIZE;

    /**
     * @static
     * @private
     * @function
     * @returns {number} The largest multiple of #DIGIT_MAX that is less than or equal to #UINT32_MAX + 1.
     * @description Calculates the maximum valid value for the base random number before modulo,
     * to ensure an unbiased distribution for randomDigit().
     */
    static #RandomDigitUnbiasedRange = () => Math.floor((this.#UINT32_MAX + 1) / this.#DIGIT_RANGE_SIZE) * this.#DIGIT_RANGE_SIZE;

    /**
     * @static
     * @public
     * @function
     * @param {number} value - The new exclusive upper bound for random integers. Must be greater than 0.
     * @throws {TypeError} If value is not a number.
     * @throws {RangeError} If value is less than or equal to 0.
     * @description Sets the range for the randomInt() method.
     * For example, if value is 100, randomInt() will generate integers from 0 to 99.
     * A warning will be issued if the value significantly exceeds the underlying 32-bit random number generator's maximum,
     * as this may lead to non-uniform distribution over the entire requested range.
     */
    static setRange = (value) => {
        // Check if the value is a number and greater than 0
        if (typeof value !== 'number')
            throw new TypeError('Value must be a number.');
        if (value < 1)
            throw new RangeError('Value must be greater than 0.');
        if (value > this.#UINT32_MAX + 1)
            console.warn(
                `RandomUtils.setRange: The provided range value (${value}) significantly exceeds ` +
                `the maximum output of the underlying 32-bit random number generator (${this.#UINT32_MAX + 1}). ` +
                `While randomInt() will still produce numbers up to ${this.#UINT32_MAX}, ` +
                `it cannot uniformly cover the entire requested range [0, ${value - 1}]. ` +
                `The distribution will be uniform only up to ${this.#UINT32_MAX}.`
            );
        this.#randomIntRange = value;
    }

    /**
     * @static
     * @public
     * @function
     * @returns {number} The current exclusive upper bound for randomInt().
     * @description Gets the current range (exclusive upper bound) for the randomInt() method.
     */
    static getRange = () => this.#randomIntRange;

    /**
     * @static
     * @public
     * @function
     * @returns {number} A random integer between 0 (inclusive) and the current range (exclusive).
     * @description Generates a random integer within the range [0, getRange() - 1].
     * Uses a rejection sampling method to avoid modulo bias.
     */
    static randomInt = () => {
        let randomVal;
        const currentMaxValid = this.#RandomIntUnbiasedRange(); // Cache the value
        do
            randomVal = this.#base();
        while (randomVal >= currentMaxValid && currentMaxValid > 0); // Add check for currentMaxValid > 0 to prevent infinite loop if range is too large
        if (currentMaxValid === 0)
            return this.#base() % this.#randomIntRange;
        return randomVal % this.#randomIntRange;
    }

    /**
     * @static
     * @public
     * @function
     * @returns {string} A random lowercase letter ('a' through 'z').
     * @description Generates a random lowercase English letter.
     * Uses a rejection sampling method to avoid modulo bias.
     */
    static randomLetter = () => {
        let randomVal;
        const currentMaxValid = this.#RandomLetterUnbiasedRange(); // Cache the value
        do
            randomVal = this.#base();
        while (randomVal >= currentMaxValid && currentMaxValid > 0); // Add check for currentMaxValid > 0 to prevent infinite loop if range is too large
        return String.fromCharCode('a'.charCodeAt(0) + randomVal % this.#LETTER_RANGE_SIZE);
    }

    /**
     * @static
     * @public
     * @function
     * @returns {string} A random digit character ('0' through '9').
     * @description Generates a random digit character.
     * Uses a rejection sampling method to avoid modulo bias.
     */
    static randomDigit = () => {
        let randomVal;
        const currentMaxValid = this.#RandomDigitUnbiasedRange(); // Cache the value
        do
            randomVal = this.#base();
        while (randomVal >= currentMaxValid && currentMaxValid > 0); // Add check for currentMaxValid > 0 to prevent infinite loop if range is too large
        return String.fromCharCode('0'.charCodeAt(0) + randomVal % this.#DIGIT_RANGE_SIZE);
    }
}