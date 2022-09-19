import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="765"
		and not target_0.getValue()="768"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="779"
		and not target_1.getValue()="782"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="785"
		and not target_2.getValue()="788"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="789"
		and not target_3.getValue()="792"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="793"
		and not target_4.getValue()="796"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="802"
		and not target_5.getValue()="805"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="807"
		and not target_6.getValue()="810"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="824"
		and not target_7.getValue()="827"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="830"
		and not target_8.getValue()="833"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="855"
		and not target_9.getValue()="858"
		and target_9.getEnclosingFunction() = func)
}

predicate func_12(Parameter vparams) {
	exists(EQExpr target_12 |
		target_12.getType().hasName("int")
		and target_12.getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_12.getLeftOperand().(PointerFieldAccess).getType().hasName("int")
		and target_12.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="base"
		and target_12.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("ASN1_OCTET_STRING *")
		and target_12.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams
		and target_12.getRightOperand().(Literal).getValue()="0"
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="order"
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="base"
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getType().hasName("int")
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="base"
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams
		and target_12.getParent().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_12.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_12.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="16"
		and target_12.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="263"
		and target_12.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="115"
		and target_12.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="crypto/ec/ec_asn1.c"
		and target_12.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="768")
}

predicate func_13(Parameter vparams) {
	exists(PointerFieldAccess target_13 |
		target_13.getTarget().getName()="order"
		and target_13.getType().hasName("ASN1_INTEGER *")
		and target_13.getQualifier().(VariableAccess).getTarget()=vparams)
}

predicate func_14(Parameter vparams) {
	exists(PointerFieldAccess target_14 |
		target_14.getTarget().getName()="base"
		and target_14.getType().hasName("ASN1_OCTET_STRING *")
		and target_14.getQualifier().(VariableAccess).getTarget()=vparams)
}

predicate func_15(Parameter vparams) {
	exists(PointerFieldAccess target_15 |
		target_15.getTarget().getName()="data"
		and target_15.getType().hasName("unsigned char *")
		and target_15.getQualifier().(PointerFieldAccess).getTarget().getName()="base"
		and target_15.getQualifier().(PointerFieldAccess).getType().hasName("ASN1_OCTET_STRING *")
		and target_15.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams)
}

from Function func, Parameter vparams
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
and not func_12(vparams)
and func_13(vparams)
and func_14(vparams)
and func_15(vparams)
and vparams.getType().hasName("const ECPARAMETERS *")
and vparams.getParentScope+() = func
select func, vparams
