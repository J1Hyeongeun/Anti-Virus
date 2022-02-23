# 다양성 추가
# _*_coding:utf-8 _*_
import sys
import os
import hashlib

virusDB = [
    '68:44d88612fea8a8f36de82e1278abb02f:EICAR Test',
    '65:77bff0b143e4840ae73d4582a8914a43:Dummy Test'
]

vdb = [] # virusDB 가공하여 저장
vsize = [] # 악성코드의 파일 크기만 저장

# virusDB 가공 -> vDB 저장
def MakeVDB() :
    for pattern in virusDB :
        t = []
        v = pattern.split(':') # : 기준으로 자르기
        t.append(v[1]) # MD5 해시 저장
        t.append(v[2]) # Virus 이름 저장
        vdb.append(t) # 최종 vDB에 저장

        size = int(v[0]) # virus 파일 크기
        if vsize.count(size) == 0 : # 이미 해당 크기가 등록되었는지 검사
            vsize.append(size)

# virus 검사
def SearchVDB(fmd5) :
    for t in vdb :
        if t[0] == fmd5 : # MD5 해시가 같은지 비교
            return True, t[1] # 악성코드 이름을 함께 리턴

    return False, '' # 악성코드 발견 X

if __name__ == '__main__' :
    MakeVDB() # 악성코드 DB 가공

    # 커맨드라인으로 악성코드 검사 가능
    # 커맨드라인의 입력 방식을 체크
    if len(sys.argv) != 2 :
        print 'Usage : antivirus.py [file]'
        exit(0)

    fname = sys.argv[1] # 악성코드 검사 대상 파일

    size = os.path.getsize(fname) # 검사 대상 파일 크기 구함
    if vsize.count(size) :
        fp = open(fname, 'rb') # 바이너리 모드로 읽기
        buf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest()

        ret, vname = SearchVDB(fmd5) # 악성코드 검사
        if ret == True :
            print '%s : %s' % (fname, vname)
            os.remove(fname) # 파일을 삭제 -> 치료
        else :
            print '%s : ok' % (fname)
    else:
        print '%s : ok' % (fname)