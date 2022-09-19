import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1703"
		and not target_0.getValue()="1709"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1711"
		and not target_1.getValue()="1717"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1717"
		and not target_2.getValue()="1723"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="1723"
		and not target_3.getValue()="1734"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="1731"
		and not target_4.getValue()="1742"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="1737"
		and not target_5.getValue()="1748"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="1765"
		and not target_6.getValue()="1781"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="1776"
		and not target_7.getValue()="1792"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="1793"
		and not target_8.getValue()="1809"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="1801"
		and not target_9.getValue()="1817"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="1808"
		and not target_10.getValue()="1824"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="1814"
		and not target_11.getValue()="1830"
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Literal target_12 |
		target_12.getValue()="1818"
		and not target_12.getValue()="1834"
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(Literal target_13 |
		target_13.getValue()="1829"
		and not target_13.getValue()="1845"
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(Literal target_14 |
		target_14.getValue()="1838"
		and not target_14.getValue()="1854"
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Function func) {
	exists(Literal target_15 |
		target_15.getValue()="1848"
		and not target_15.getValue()="1864"
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Function func) {
	exists(Literal target_16 |
		target_16.getValue()="1884"
		and not target_16.getValue()="1900"
		and target_16.getEnclosingFunction() = func)
}

predicate func_17(Function func) {
	exists(Literal target_17 |
		target_17.getValue()="1896"
		and not target_17.getValue()="1912"
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(Function func) {
	exists(Literal target_18 |
		target_18.getValue()="1914"
		and not target_18.getValue()="1930"
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(Function func) {
	exists(Literal target_19 |
		target_19.getValue()="1926"
		and not target_19.getValue()="1942"
		and target_19.getEnclosingFunction() = func)
}

predicate func_20(Function func) {
	exists(Literal target_20 |
		target_20.getValue()="1952"
		and not target_20.getValue()="1968"
		and target_20.getEnclosingFunction() = func)
}

predicate func_21(Function func) {
	exists(Literal target_21 |
		target_21.getValue()="1958"
		and not target_21.getValue()="1974"
		and target_21.getEnclosingFunction() = func)
}

predicate func_22(Function func) {
	exists(Literal target_22 |
		target_22.getValue()="1973"
		and not target_22.getValue()="1989"
		and target_22.getEnclosingFunction() = func)
}

predicate func_23(Function func) {
	exists(Literal target_23 |
		target_23.getValue()="1983"
		and not target_23.getValue()="1999"
		and target_23.getEnclosingFunction() = func)
}

predicate func_24(Function func) {
	exists(Literal target_24 |
		target_24.getValue()="1988"
		and not target_24.getValue()="2004"
		and target_24.getEnclosingFunction() = func)
}

predicate func_25(Variable valg_k, Variable vdh) {
	exists(IfStmt target_25 |
		target_25.getCondition().(EQExpr).getType().hasName("int")
		and target_25.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_25.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("int")
		and target_25.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_25.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("BIGNUM *")
		and target_25.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh
		and target_25.getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="141"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="395"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_clnt.c"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1703"
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getType().hasName("long")
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=valg_k
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

predicate func_26(Variable valg_k, Variable vdh) {
	exists(IfStmt target_26 |
		target_26.getCondition().(EQExpr).getType().hasName("int")
		and target_26.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_26.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("int")
		and target_26.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="g"
		and target_26.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("BIGNUM *")
		and target_26.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh
		and target_26.getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="141"
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="375"
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_clnt.c"
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1729"
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getType().hasName("long")
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=valg_k
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

predicate func_27(Variable valg_k, Variable vdh) {
	exists(IfStmt target_27 |
		target_27.getCondition().(EQExpr).getType().hasName("int")
		and target_27.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_27.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("int")
		and target_27.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_27.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("BIGNUM *")
		and target_27.getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh
		and target_27.getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="141"
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="393"
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_clnt.c"
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1755"
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getType().hasName("long")
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=valg_k
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

from Function func, Variable valg_k, Variable vdh
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
and func_6(func)
and func_7(func)
and func_8(func)
and func_9(func)
and func_10(func)
and func_11(func)
and func_12(func)
and func_13(func)
and func_14(func)
and func_15(func)
and func_16(func)
and func_17(func)
and func_18(func)
and func_19(func)
and func_20(func)
and func_21(func)
and func_22(func)
and func_23(func)
and func_24(func)
and not func_25(valg_k, vdh)
and not func_26(valg_k, vdh)
and not func_27(valg_k, vdh)
and valg_k.getType().hasName("long")
and vdh.getType().hasName("DH *")
and valg_k.getParentScope+() = func
and vdh.getParentScope+() = func
select func, valg_k, vdh
