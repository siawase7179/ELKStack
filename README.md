# Elasticsearch

- Elasticsearch는 문서 데이터와 상호 작용하기 위한 RESTFul JSON기반 API를 제공합니다. 적절한 클러스터 엔드포인트로 HTTP 요청을 전송하여 문서를 색인, 검색, 업데이트 및 삭제할 수 있습니다.
- RDB에서 like 구문을 넣으면 full scan이 발생하지만 elasticsearch의 경우 역 색인을 통해 바로 접근 가능
- JSON 형태로 데이터를 저장하며 각 Document의 키와 값을 가지고 인덱스를 생성

> [!NOTE]
> 역 인덱스
> 책의 맨 뒤에 있는 주요 키워드에 대한 내용이 몇 페이지에 있는지 볼 수 있는 찾아보기 페이지에 비유할 수 있습니다. Elasticsearch에서는 추출된 각 키워드를 텀(term) 이라고 부릅니다.
>

# 1. 구성도
![image](https://github.com/siawase7179/ELKStack/assets/152139618/0b521921-451a-4314-8e67-aa8d6a6f79f5)
