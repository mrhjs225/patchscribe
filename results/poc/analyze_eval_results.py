#!/usr/bin/env python3
"""
분석 스크립트: 각 모델별로 minimal, formal, natural, only_natural에 따른
평균 점수와 평균 등수를 계산
"""

import json
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple

def parse_eval_file(filepath: Path) -> Dict[str, Dict[str, Tuple[float, int]]]:
    """
    eval.md 파일을 파싱하여 각 케이스별로 옵션별 점수와 등수를 추출
    
    Returns:
        {case_name: {option: (score, rank)}}
    """
    content = filepath.read_text()
    
    results = {}
    current_case = None
    
    # 케이스와 옵션 정보를 추출
    case_pattern = r'## Case: (.+)'
    option_pattern = r'- \*\*Option ([A-D])\*\* — Score: (\d+)/3'
    ranking_pattern = r'- \*\*Ranking\*\*: (.+)'
    
    lines = content.split('\n')
    
    for i, line in enumerate(lines):
        # 케이스 찾기
        case_match = re.match(case_pattern, line)
        if case_match:
            current_case = case_match.group(1)
            results[current_case] = {}
            continue
        
        # 옵션 점수 찾기
        option_match = re.match(option_pattern, line)
        if option_match and current_case:
            option = option_match.group(1)
            score = int(option_match.group(2))
            results[current_case][option] = [score, None]  # [score, rank]
            continue
        
        # 랭킹 찾기
        ranking_match = re.match(ranking_pattern, line)
        if ranking_match and current_case:
            ranking_str = ranking_match.group(1)
            # "B (1st) > A (2nd) > C (3rd) > D (4th)" 형식 파싱
            rank_parts = ranking_str.split(' > ')
            for part in rank_parts:
                match = re.match(r'([A-D]) \((\d+)[a-z]+\)', part)
                if match:
                    option = match.group(1)
                    rank = int(match.group(2))
                    if option in results[current_case]:
                        results[current_case][option][1] = rank
    
    return results

def load_key_file(filepath: Path) -> Dict[str, Dict[str, str]]:
    """
    key.json 파일을 로드
    
    Returns:
        {case_name: {option: explanation_type}}
    """
    with open(filepath, 'r') as f:
        return json.load(f)

def calculate_statistics(model_name: str, eval_file: Path, key_file: Path):
    """
    특정 모델에 대한 통계를 계산
    """
    eval_data = parse_eval_file(eval_file)
    key_data = load_key_file(key_file)
    
    # 각 설명 타입별로 점수와 랭크를 수집
    type_scores = defaultdict(list)  # {explanation_type: [scores]}
    type_ranks = defaultdict(list)   # {explanation_type: [ranks]}
    
    for case_name, key_mapping in key_data.items():
        if case_name not in eval_data:
            print(f"Warning: {case_name} not found in eval data for {model_name}")
            continue
        
        for option, exp_type in key_mapping.items():
            if option in eval_data[case_name]:
                score, rank = eval_data[case_name][option]
                if score is not None:
                    type_scores[exp_type].append(score)
                if rank is not None:
                    type_ranks[exp_type].append(rank)
    
    # 평균 계산
    results = {}
    for exp_type in ['minimal', 'formal', 'natural', 'only_natural']:
        if exp_type in type_scores and type_scores[exp_type]:
            avg_score = sum(type_scores[exp_type]) / len(type_scores[exp_type])
            avg_rank = sum(type_ranks[exp_type]) / len(type_ranks[exp_type])
            count = len(type_scores[exp_type])
            results[exp_type] = {
                'avg_score': avg_score,
                'avg_rank': avg_rank,
                'count': count
            }
        else:
            results[exp_type] = {
                'avg_score': 0.0,
                'avg_rank': 0.0,
                'count': 0
            }
    
    return results

def main():
    models = ['deepseek-r1', 'gemma3', 'gpt-oss', 'llama3.2', 'qwen3']
    base_path = Path('/home/hjs/research/patchscribe/results/poc')
    
    all_results = {}
    
    for model in models:
        eval_file = base_path / f'zeroday_blind_{model}_eval.md'
        key_file = base_path / f'zeroday_blind_{model}_key.json'
        
        if not eval_file.exists() or not key_file.exists():
            print(f"Warning: Files for {model} not found")
            continue
        
        results = calculate_statistics(model, eval_file, key_file)
        all_results[model] = results
    
    # 결과 출력 (마크다운 테이블 형식)
    print("\n# 모델별 평가 결과 요약\n")
    
    for model, results in all_results.items():
        print(f"\n## {model}\n")
        print("| Explanation Type | Avg Score | Avg Rank | Count |")
        print("|-----------------|-----------|----------|-------|")
        for exp_type in ['minimal', 'formal', 'natural', 'only_natural']:
            data = results[exp_type]
            print(f"| {exp_type:15} | {data['avg_score']:.3f} | {data['avg_rank']:.3f} | {data['count']:5} |")
    
    # 전체 비교 테이블
    print("\n## 모델 간 비교 (평균 점수)\n")
    print("| Model | minimal | formal | natural | only_natural |")
    print("|-------|---------|--------|---------|--------------|")
    for model, results in all_results.items():
        scores = [results[t]['avg_score'] for t in ['minimal', 'formal', 'natural', 'only_natural']]
        print(f"| {model:12} | {scores[0]:.3f} | {scores[1]:.3f} | {scores[2]:.3f} | {scores[3]:.3f} |")
    
    print("\n## 모델 간 비교 (평균 등수, 낮을수록 좋음)\n")
    print("| Model | minimal | formal | natural | only_natural |")
    print("|-------|---------|--------|---------|--------------|")
    for model, results in all_results.items():
        ranks = [results[t]['avg_rank'] for t in ['minimal', 'formal', 'natural', 'only_natural']]
        print(f"| {model:12} | {ranks[0]:.3f} | {ranks[1]:.3f} | {ranks[2]:.3f} | {ranks[3]:.3f} |")

if __name__ == '__main__':
    main()
