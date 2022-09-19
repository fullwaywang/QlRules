import cpp

predicate func_0(Variable vret) {
	exists(GTExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vret
		and target_0.getLesserOperand().(Literal).getValue()="0")
}

predicate func_1(Parameter vctx, Variable vret) {
	exists(BlockStmt target_1 |
		target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("int")
		and target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="error"
		and target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("int")
		and target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_1.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getType().hasName("int")
		and target_1.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret
		and target_1.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getCondition().(LTExpr).getType().hasName("int")
		and target_1.getParent().(IfStmt).getCondition().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vret
		and target_1.getParent().(IfStmt).getCondition().(LTExpr).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_2(Parameter vctx, Variable vret) {
	exists(BlockStmt target_2 |
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("int")
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="error"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("int")
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="79"
		and target_2.getParent().(IfStmt).getParent().(IfStmt).getCondition().(LTExpr).getType().hasName("int")
		and target_2.getParent().(IfStmt).getParent().(IfStmt).getCondition().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vret
		and target_2.getParent().(IfStmt).getParent().(IfStmt).getCondition().(LTExpr).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_3(Parameter vctx, Variable vx, Variable vret) {
	exists(LogicalAndExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_3.getLeftOperand().(LogicalAndExpr).getLeftOperand().(GTExpr).getType().hasName("int")
		and target_3.getLeftOperand().(LogicalAndExpr).getLeftOperand().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vret
		and target_3.getLeftOperand().(LogicalAndExpr).getLeftOperand().(GTExpr).getLesserOperand().(Literal).getValue()="0"
		and target_3.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getType().hasName("int")
		and target_3.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(BitwiseAndExpr).getType().hasName("unsigned int")
		and target_3.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ex_flags"
		and target_3.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx
		and target_3.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="16"
		and target_3.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_3.getRightOperand().(NEExpr).getType().hasName("int")
		and target_3.getRightOperand().(NEExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ex_pathlen"
		and target_3.getRightOperand().(NEExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("long")
		and target_3.getRightOperand().(NEExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx
		and target_3.getRightOperand().(NEExpr).getRightOperand().(UnaryMinusExpr).getType().hasName("int")
		and target_3.getRightOperand().(NEExpr).getRightOperand().(UnaryMinusExpr).getValue()="-1"
		and target_3.getRightOperand().(NEExpr).getRightOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_3.getParent().(LogicalAndExpr).getRightOperand().(BitwiseAndExpr).getType().hasName("unsigned long")
		and target_3.getParent().(LogicalAndExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_3.getParent().(LogicalAndExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("unsigned long")
		and target_3.getParent().(LogicalAndExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="param"
		and target_3.getParent().(LogicalAndExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_3.getParent().(LogicalAndExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="32"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="error"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="41"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_4(Parameter vctx, Variable vx, Variable vnum, Variable vret) {
	exists(BitwiseAndExpr target_4 |
		target_4.getType().hasName("unsigned long")
		and target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_4.getLeftOperand().(PointerFieldAccess).getType().hasName("unsigned long")
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="param"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("X509_VERIFY_PARAM *")
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_4.getRightOperand().(Literal).getValue()="32"
		and target_4.getParent().(LogicalAndExpr).getRightOperand().(GTExpr).getType().hasName("int")
		and target_4.getParent().(LogicalAndExpr).getRightOperand().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vnum
		and target_4.getParent().(LogicalAndExpr).getRightOperand().(GTExpr).getLesserOperand().(Literal).getValue()="1"
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("check_curve")
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vx
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vret
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="error"
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(IfStmt).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vret
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="error"
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="79")
}

predicate func_7(Variable vx) {
	exists(EQExpr target_7 |
		target_7.getType().hasName("int")
		and target_7.getLeftOperand().(BitwiseAndExpr).getType().hasName("unsigned int")
		and target_7.getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ex_flags"
		and target_7.getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("uint32_t")
		and target_7.getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx
		and target_7.getLeftOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="16"
		and target_7.getRightOperand().(Literal).getValue()="0")
}

predicate func_8(Variable vx) {
	exists(NEExpr target_8 |
		target_8.getType().hasName("int")
		and target_8.getLeftOperand().(PointerFieldAccess).getTarget().getName()="ex_pathlen"
		and target_8.getLeftOperand().(PointerFieldAccess).getType().hasName("long")
		and target_8.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx
		and target_8.getRightOperand().(UnaryMinusExpr).getType().hasName("int")
		and target_8.getRightOperand().(UnaryMinusExpr).getValue()="-1"
		and target_8.getRightOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

from Function func, Parameter vctx, Variable vx, Variable vnum, Variable vret
where
not func_0(vret)
and not func_1(vctx, vret)
and not func_2(vctx, vret)
and not func_3(vctx, vx, vret)
and func_4(vctx, vx, vnum, vret)
and func_7(vx)
and func_8(vx)
and vctx.getType().hasName("X509_STORE_CTX *")
and vx.getType().hasName("X509 *")
and vnum.getType().hasName("int")
and vret.getType().hasName("int")
and vctx.getParentScope+() = func
and vx.getParentScope+() = func
and vnum.getParentScope+() = func
and vret.getParentScope+() = func
select func, vctx, vx, vnum, vret
