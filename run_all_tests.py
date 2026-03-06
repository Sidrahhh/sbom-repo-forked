"""
Comprehensive Test Runner for PRISM
==================================

Runs all test suites and generates complete validation report:
- Objective 1 tests
- Objective 2 tests
- Benchmarking
- Ablation study
- Metrics generation

Usage:
    python run_all_tests.py
    python run_all_tests.py --objective1
    python run_all_tests.py --objective2
    python run_all_tests.py --benchmarking
    python run_all_tests.py --quick  # Skip slow tests
"""

import sys
import subprocess
import argparse
from pathlib import Path
from datetime import datetime


def run_test_suite(test_file, description, args):
    """Run a specific test suite"""
    print("\n" + "="*80)
    print(f"RUNNING: {description}")
    print("="*80)

    cmd = ["pytest", f"tests/{test_file}", "-v"]

    if args.verbose:
        cmd.append("-vv")

    if args.capture_no:
        cmd.append("-s")

    result = subprocess.run(cmd, capture_output=False)

    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description="Run PRISM test suites")
    parser.add_argument("--objective1", action="store_true", help="Run only Objective 1 tests")
    parser.add_argument("--objective2", action="store_true", help="Run only Objective 2 tests")
    parser.add_argument("--benchmarking", action="store_true", help="Run only benchmarking tests")
    parser.add_argument("--ablation", action="store_true", help="Run only ablation study")
    parser.add_argument("--metrics", action="store_true", help="Run only metrics generation")
    parser.add_argument("--quick", action="store_true", help="Skip slow tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--capture-no", "-s", action="store_true", help="Don't capture output")

    args = parser.parse_args()

    # Determine which tests to run
    run_all = not any([args.objective1, args.objective2, args.benchmarking,
                       args.ablation, args.metrics])

    test_suites = []

    if run_all or args.objective1:
        test_suites.append(("test_objective_1.py", "Objective 1: Multi-Feed Correlation"))

    if run_all or args.objective2:
        test_suites.append(("test_objective_2.py", "Objective 2: Reachability & AI"))

    if run_all or args.benchmarking:
        test_suites.append(("test_benchmarking.py", "Benchmarking vs Traditional Tools"))

    if run_all or args.ablation:
        test_suites.append(("test_ablation_study.py", "Ablation Study"))

    if run_all or args.metrics:
        test_suites.append(("test_generate_metrics.py", "Metrics Generation"))

    # Run all test suites
    print("\n" + "="*80)
    print("PRISM COMPREHENSIVE TEST SUITE")
    print("="*80)
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Test Suites: {len(test_suites)}")
    print("="*80)

    results = {}
    for test_file, description in test_suites:
        success = run_test_suite(test_file, description, args)
        results[description] = success

    # Print summary
    print("\n" + "="*80)
    print("TEST EXECUTION SUMMARY")
    print("="*80)
    print(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\nResults:")

    passed = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)

    for test_name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {status} - {test_name}")

    print(f"\n📊 Total: {passed}/{len(results)} test suites passed")

    if failed == 0:
        print("\n🎉 ALL TESTS PASSED!")
        print("\n📁 Generated Outputs:")
        print("  - output/objective1_results.txt")
        print("  - output/objective2_results.txt")
        print("  - output/benchmark_comparison.txt")
        print("  - output/ablation_study.txt")
        print("  - output/complete_metrics_report.txt")
        print("  - output/visualization_data.json")
        print("\n📈 Next Steps:")
        print("  1. Review metrics in output/ directory")
        print("  2. Run: python output/generate_graphs.py")
        print("  3. Use tables/graphs in PPT presentation")
        return 0
    else:
        print(f"\n⚠️ {failed} test suite(s) failed - review output above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
