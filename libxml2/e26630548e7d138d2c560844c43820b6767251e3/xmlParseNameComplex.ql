import cpp

predicate func_0(Parameter vctxt_3317) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="end"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317)
}

predicate func_1(Parameter vctxt_3317) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="cur"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317)
}

predicate func_2(Parameter vctxt_3317) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("xmlParserHandlePEReference")
		and not target_2.getTarget().hasName("xmlFatalErr")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vctxt_3317)
}

predicate func_3(Variable vc_3319) {
	exists(VariableAccess target_3 |
		target_3.getTarget()=vc_3319
		and target_3.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_3.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof AssignExpr
		and target_3.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_3.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof EmptyStmt
		and target_3.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3) instanceof IfStmt
		and target_3.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4) instanceof ExprStmt)
}

predicate func_6(Function func) {
	exists(StringLiteral target_6 |
		target_6.getValue()="unexpected change of input buffer"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Parameter vctxt_3317) {
	exists(ReturnStmt target_7 |
		target_7.getExpr() instanceof Literal
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="base"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int"))
}

predicate func_8(Parameter vctxt_3317) {
	exists(PointerDereferenceExpr target_8 |
		target_8.getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_8.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_8.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_8.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_8.getParent().(EQExpr).getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_14(Function func) {
	exists(Literal target_14 |
		target_14.getValue()="0"
		and target_14.getEnclosingFunction() = func)
}

predicate func_17(Parameter vctxt_3317) {
	exists(IfStmt target_17 |
		target_17.getCondition().(EqualityOperation).getAnOperand() instanceof PointerDereferenceExpr
		and target_17.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="37"
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlParserHandlePEReference")
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3317)
}

predicate func_20(Parameter vctxt_3317, Variable vl_3318, Variable vc_3319, Variable vcount_3320) {
	exists(IfStmt target_20 |
		target_20.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc_3319
		and target_20.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_3320
		and target_20.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_20.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlGROW")
		and target_20.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3317
		and target_20.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_20.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_3319
		and target_20.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlCurrentChar")
		and target_20.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3317
		and target_20.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_3318)
}

from Function func, Parameter vctxt_3317, Variable vl_3318, Variable vc_3319, Variable vcount_3320
where
func_0(vctxt_3317)
and func_1(vctxt_3317)
and func_2(vctxt_3317)
and func_3(vc_3319)
and not func_6(func)
and not func_7(vctxt_3317)
and func_8(vctxt_3317)
and func_14(func)
and func_17(vctxt_3317)
and func_20(vctxt_3317, vl_3318, vc_3319, vcount_3320)
and vctxt_3317.getType().hasName("xmlParserCtxtPtr")
and vl_3318.getType().hasName("int")
and vc_3319.getType().hasName("int")
and vcount_3320.getType().hasName("int")
and vctxt_3317.getParentScope+() = func
and vl_3318.getParentScope+() = func
and vc_3319.getParentScope+() = func
and vcount_3320.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
