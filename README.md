# tcp-caohejing
TCP 漕河泾(科技绿洲)算法的简易版本

up和down两个state之间转换：
- 如果实际delivery rate增益小于a%，转为down，gain<1;
- 如果实际delivery rate损失大于b%，转为up，gain>1;
