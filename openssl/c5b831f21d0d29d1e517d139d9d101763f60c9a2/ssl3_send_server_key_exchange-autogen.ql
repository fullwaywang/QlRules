import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1694"
		and not target_0.getValue()="1691"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="5"
		and not target_1.getValue()="43"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1701"
		and not target_2.getValue()="1731"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="1730"
		and not target_3.getValue()="1719"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="1736"
		and not target_4.getValue()="1725"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="1742"
		and not target_5.getValue()="1731"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="1748"
		and not target_6.getValue()="1737"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="1758"
		and not target_7.getValue()="1747"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="1766"
		and not target_8.getValue()="1755"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="1773"
		and not target_9.getValue()="1762"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="1786"
		and not target_10.getValue()="1775"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="1800"
		and not target_11.getValue()="1789"
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Literal target_12 |
		target_12.getValue()="1804"
		and not target_12.getValue()="1793"
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(Literal target_13 |
		target_13.getValue()="1814"
		and not target_13.getValue()="1803"
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(Literal target_14 |
		target_14.getValue()="1853"
		and not target_14.getValue()="1842"
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Function func) {
	exists(Literal target_15 |
		target_15.getValue()="1865"
		and not target_15.getValue()="1854"
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Function func) {
	exists(Literal target_16 |
		target_16.getValue()="1892"
		and not target_16.getValue()="1881"
		and target_16.getEnclosingFunction() = func)
}

predicate func_17(Function func) {
	exists(Literal target_17 |
		target_17.getValue()="1968"
		and not target_17.getValue()="1957"
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(Function func) {
	exists(Literal target_18 |
		target_18.getValue()="1977"
		and not target_18.getValue()="1966"
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(Function func) {
	exists(Literal target_19 |
		target_19.getValue()="1991"
		and not target_19.getValue()="1980"
		and target_19.getEnclosingFunction() = func)
}

predicate func_20(Function func) {
	exists(Literal target_20 |
		target_20.getValue()="2007"
		and not target_20.getValue()="1996"
		and target_20.getEnclosingFunction() = func)
}

predicate func_21(Function func) {
	exists(Literal target_21 |
		target_21.getValue()="2019"
		and not target_21.getValue()="2008"
		and target_21.getEnclosingFunction() = func)
}

predicate func_22(Parameter vs) {
	exists(PointerFieldAccess target_22 |
		target_22.getTarget().getName()="options"
		and target_22.getType().hasName("unsigned long")
		and target_22.getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_23(Variable vdh) {
	exists(PointerFieldAccess target_23 |
		target_23.getTarget().getName()="pub_key"
		and target_23.getType().hasName("BIGNUM *")
		and target_23.getQualifier().(VariableAccess).getTarget()=vdh)
}

predicate func_24(Variable vdh, Variable vdhp, Variable vtype, Function func) {
	exists(IfStmt target_24 |
		target_24.getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_24.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_24.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getType().hasName("int")
		and target_24.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_24.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdhp
		and target_24.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_24.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getType().hasName("int")
		and target_24.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="priv_key"
		and target_24.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdhp
		and target_24.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_24.getCondition().(LogicalOrExpr).getRightOperand().(BitwiseAndExpr).getType().hasName("unsigned long")
		and target_24.getCondition().(LogicalOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand() instanceof PointerFieldAccess
		and target_24.getCondition().(LogicalOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1048576"
		and target_24.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_24.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DH_generate_key")
		and target_24.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdh
		and target_24.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_24.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_24.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="155"
		and target_24.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_24.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_24.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_24.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("BIGNUM *")
		and target_24.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_24.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh
		and target_24.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_dup")
		and target_24.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_24.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdhp
		and target_24.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getType().hasName("BIGNUM *")
		and target_24.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="priv_key"
		and target_24.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh
		and target_24.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_dup")
		and target_24.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="priv_key"
		and target_24.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdhp
		and target_24.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_24.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand() instanceof PointerFieldAccess
		and target_24.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_24.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="priv_key"
		and target_24.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh
		and target_24.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_24.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_24.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_24.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="155"
		and target_24.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_24.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_24.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_24.getEnclosingFunction() = func
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getType().hasName("unsigned long")
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vtype
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

from Function func, Variable vdh, Variable vdhp, Variable vtype, Parameter vs
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
and func_22(vs)
and func_23(vdh)
and func_24(vdh, vdhp, vtype, func)
and vdh.getType().hasName("DH *")
and vdhp.getType().hasName("DH *")
and vtype.getType().hasName("unsigned long")
and vs.getType().hasName("SSL *")
and vdh.getParentScope+() = func
and vdhp.getParentScope+() = func
and vtype.getParentScope+() = func
and vs.getParentScope+() = func
select func, vdh, vdhp, vtype, vs
