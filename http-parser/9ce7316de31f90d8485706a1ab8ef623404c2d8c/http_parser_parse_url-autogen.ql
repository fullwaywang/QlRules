/**
 * @name http-parser-9ce7316de31f90d8485706a1ab8ef623404c2d8c-http_parser_parse_url
 * @id cpp/http-parser/9ce7316de31f90d8485706a1ab8ef623404c2d8c-http-parser-parse-url
 * @description http-parser-9ce7316de31f90d8485706a1ab8ef623404c2d8c-http_parser.c-http_parser_parse_url
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(BitwiseAndExpr target_15, Function func) {
        exists(ExprStmt target_1 |
                target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("uint16_t")
                and target_1.getExpr().(AssignExpr).getRValue() instanceof ValueFieldAccess
                and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_1
                and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
                and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vu_2282, BitwiseAndExpr target_15, ArrayExpr target_16, ExprStmt target_17) {
        exists(ExprStmt target_2 |
                target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("uint16_t")
                and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="len"
                and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="field_data"
                and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vu_2282
                and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_2
                and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
                and target_16.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
                and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vbuf_2281, BitwiseAndExpr target_15, EqualityOperation target_18) {
        exists(ExprStmt target_3 |
                target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("const char *")
                and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_2281
                and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("uint16_t")
                and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("uint16_t")
                and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_3
                and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
                and target_18.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_4(Parameter vbuf_2281, EqualityOperation target_18) {
        exists(PointerArithmeticOperation target_4 |
                target_4.getAnOperand().(VariableAccess).getTarget()=vbuf_2281
                and target_4.getAnOperand().(VariableAccess).getType().hasName("uint16_t")
                and target_4.getParent().(PointerAddExpr).getParent().(FunctionCall).getParent().(Initializer).getExpr() instanceof FunctionCall
                and target_18.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_6(BitwiseAndExpr target_15, Function func) {
        exists(ExprStmt target_6 |
                target_6.getExpr().(CommaExpr).getLeftOperand().(SizeofExprOperator).getValue()="4"
                and target_6.getExpr().(CommaExpr).getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(StringLiteral).getValue()="Port number overflow"
                and target_6.getExpr().(CommaExpr).getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__assert_fail")
                and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(8)=target_6
                and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
                and target_6.getEnclosingFunction() = func)
}

predicate func_7(Variable vv_2371, BitwiseAndExpr target_15) {
        exists(ExprStmt target_7 |
                target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vv_2371
                and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
                and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_7
                and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15)
}

predicate func_8(Parameter vbuf_2281, Variable vv_2371, BitwiseAndExpr target_15, PointerArithmeticOperation target_19, RelationalOperation target_20) {
        exists(ForStmt target_8 |
                target_8.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("const char *")
                and target_8.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_2281
                and target_8.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("uint16_t")
                and target_8.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("const char *")
                and target_8.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("const char *")
                and target_8.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("const char *")
                and target_8.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignMulExpr).getLValue().(VariableAccess).getTarget()=vv_2371
                and target_8.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignMulExpr).getRValue() instanceof Literal
                and target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vv_2371
                and target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("const char *")
                and target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(SubExpr).getRightOperand().(CharLiteral).getValue()="48"
                and target_8.getStmt().(BlockStmt).getStmt(2) instanceof IfStmt
                and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(10)=target_8
                and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
                and target_19.getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
                and target_8.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignMulExpr).getLValue().(VariableAccess).getLocation().isBefore(target_20.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_9(Parameter vu_2282, ValueFieldAccess target_9) {
                target_9.getTarget().getName()="off"
                and target_9.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="field_data"
                and target_9.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vu_2282
}

predicate func_10(Variable vv_2371, BitwiseAndExpr target_15, IfStmt target_10) {
                target_10.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vv_2371
                and target_10.getCondition().(RelationalOperation).getLesserOperand().(HexLiteral).getValue()="65535"
                and target_10.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="1"
                and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

predicate func_11(Parameter vbuf_2281, VariableAccess target_11) {
                target_11.getTarget()=vbuf_2281
                and target_11.getParent().(PointerAddExpr).getParent().(FunctionCall).getParent().(Initializer).getExpr() instanceof FunctionCall
}

predicate func_14(Parameter vbuf_2281, Initializer target_14) {
                target_14.getExpr().(FunctionCall).getTarget().hasName("strtoul")
                and target_14.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_2281
                and target_14.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand() instanceof ValueFieldAccess
                and target_14.getExpr().(FunctionCall).getArgument(1) instanceof Literal
                and target_14.getExpr().(FunctionCall).getArgument(2) instanceof Literal
}

predicate func_15(Parameter vu_2282, BitwiseAndExpr target_15) {
                target_15.getLeftOperand().(PointerFieldAccess).getTarget().getName()="field_set"
                and target_15.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vu_2282
                and target_15.getRightOperand().(BinaryBitwiseOperation).getValue()="4"
}

predicate func_16(Parameter vu_2282, ArrayExpr target_16) {
                target_16.getArrayBase().(PointerFieldAccess).getTarget().getName()="field_data"
                and target_16.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vu_2282
}

predicate func_17(Parameter vu_2282, Variable vv_2371, ExprStmt target_17) {
                target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="port"
                and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vu_2282
                and target_17.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vv_2371
}

predicate func_18(Parameter vbuf_2281, Parameter vu_2282, EqualityOperation target_18) {
                target_18.getAnOperand().(FunctionCall).getTarget().hasName("http_parse_host")
                and target_18.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_2281
                and target_18.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vu_2282
                and target_18.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
                and target_18.getAnOperand().(Literal).getValue()="0"
}

predicate func_19(Parameter vbuf_2281, PointerArithmeticOperation target_19) {
                target_19.getAnOperand().(VariableAccess).getTarget()=vbuf_2281
                and target_19.getAnOperand() instanceof ValueFieldAccess
}

predicate func_20(Variable vv_2371, RelationalOperation target_20) {
                 (target_20 instanceof GTExpr or target_20 instanceof LTExpr)
                and target_20.getGreaterOperand().(VariableAccess).getTarget()=vv_2371
                and target_20.getLesserOperand().(HexLiteral).getValue()="65535"
}

from Function func, Parameter vbuf_2281, Parameter vu_2282, Variable vv_2371, ValueFieldAccess target_9, IfStmt target_10, VariableAccess target_11, Initializer target_14, BitwiseAndExpr target_15, ArrayExpr target_16, ExprStmt target_17, EqualityOperation target_18, PointerArithmeticOperation target_19, RelationalOperation target_20
where
not func_1(target_15, func)
and not func_2(vu_2282, target_15, target_16, target_17)
and not func_3(vbuf_2281, target_15, target_18)
and not func_6(target_15, func)
and not func_7(vv_2371, target_15)
and not func_8(vbuf_2281, vv_2371, target_15, target_19, target_20)
and func_9(vu_2282, target_9)
and func_10(vv_2371, target_15, target_10)
and func_11(vbuf_2281, target_11)
and func_14(vbuf_2281, target_14)
and func_15(vu_2282, target_15)
and func_16(vu_2282, target_16)
and func_17(vu_2282, vv_2371, target_17)
and func_18(vbuf_2281, vu_2282, target_18)
and func_19(vbuf_2281, target_19)
and func_20(vv_2371, target_20)
and vbuf_2281.getType().hasName("const char *")
and vu_2282.getType().hasName("http_parser_url *")
and vv_2371.getType().hasName("unsigned long")
and vbuf_2281.getFunction() = func
and vu_2282.getFunction() = func
and vv_2371.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
