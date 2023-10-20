/**
 * @name openssl-578b956fe741bf8e84055547b1e83c28dd902c73-fmtint
 * @id cpp/openssl/578b956fe741bf8e84055547b1e83c28dd902c73/fmtint
 * @description openssl-578b956fe741bf8e84055547b1e83c28dd902c73-fmtint CVE-2016-0799
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsbuffer_461, Parameter vbuffer_462, Parameter vcurrlen_463, Parameter vmaxlen_464) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_461
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_462
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_463
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_464
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_1(Parameter vsbuffer_461, Parameter vbuffer_462, Parameter vcurrlen_463, Parameter vmaxlen_464, Variable vsignvalue_466) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_461
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_462
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_463
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_464
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsignvalue_466
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vsignvalue_466)
}

predicate func_2(Parameter vsbuffer_461, Parameter vbuffer_462, Parameter vcurrlen_463, Parameter vmaxlen_464) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_461
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_462
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_463
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_464
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof PointerDereferenceExpr
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_3(Parameter vsbuffer_461, Parameter vbuffer_462, Parameter vcurrlen_463, Parameter vmaxlen_464) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_461
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_462
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_463
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_464
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_4(Parameter vsbuffer_461, Parameter vbuffer_462, Parameter vcurrlen_463, Parameter vmaxlen_464) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_461
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_462
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_463
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_464
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof ArrayExpr
		and target_4.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_7(Variable vprefix_467) {
	exists(PointerDereferenceExpr target_7 |
		target_7.getOperand().(VariableAccess).getTarget()=vprefix_467
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_8(Variable vconvert_469, Variable vplace_470) {
	exists(ArrayExpr target_8 |
		target_8.getArrayBase().(VariableAccess).getTarget()=vconvert_469
		and target_8.getArrayOffset().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vplace_470
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_9(Variable vspadlen_471) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vspadlen_471)
}

predicate func_14(Function func) {
	exists(CharLiteral target_14 |
		target_14.getValue()="32"
		and target_14.getEnclosingFunction() = func)
}

predicate func_28(Function func) {
	exists(CharLiteral target_28 |
		target_28.getValue()="48"
		and target_28.getEnclosingFunction() = func)
}

predicate func_38(Parameter vsbuffer_461, Parameter vbuffer_462, Parameter vcurrlen_463, Parameter vmaxlen_464) {
	exists(ExprStmt target_38 |
		target_38.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_38.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_461
		and target_38.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_462
		and target_38.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_463
		and target_38.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_464
		and target_38.getExpr().(FunctionCall).getArgument(4) instanceof CharLiteral)
}

predicate func_39(Parameter vsbuffer_461, Parameter vbuffer_462, Parameter vcurrlen_463, Parameter vmaxlen_464, Variable vsignvalue_466) {
	exists(ExprStmt target_39 |
		target_39.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_39.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_461
		and target_39.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_462
		and target_39.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_463
		and target_39.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_464
		and target_39.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsignvalue_466
		and target_39.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vsignvalue_466)
}

predicate func_40(Parameter vsbuffer_461, Parameter vbuffer_462, Parameter vcurrlen_463, Parameter vmaxlen_464) {
	exists(ExprStmt target_40 |
		target_40.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_40.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_461
		and target_40.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_462
		and target_40.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_463
		and target_40.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_464
		and target_40.getExpr().(FunctionCall).getArgument(4) instanceof PointerDereferenceExpr)
}

predicate func_41(Parameter vsbuffer_461, Parameter vbuffer_462, Parameter vcurrlen_463, Parameter vmaxlen_464) {
	exists(ExprStmt target_41 |
		target_41.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_41.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_461
		and target_41.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_462
		and target_41.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_463
		and target_41.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_464
		and target_41.getExpr().(FunctionCall).getArgument(4) instanceof CharLiteral)
}

predicate func_42(Parameter vsbuffer_461, Parameter vbuffer_462, Parameter vcurrlen_463, Parameter vmaxlen_464, Variable vplace_470) {
	exists(ExprStmt target_42 |
		target_42.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_42.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_461
		and target_42.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_462
		and target_42.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_463
		and target_42.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_464
		and target_42.getExpr().(FunctionCall).getArgument(4) instanceof ArrayExpr
		and target_42.getParent().(WhileStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vplace_470
		and target_42.getParent().(WhileStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0")
}

from Function func, Parameter vsbuffer_461, Parameter vbuffer_462, Parameter vcurrlen_463, Parameter vmaxlen_464, Variable vsignvalue_466, Variable vprefix_467, Variable vconvert_469, Variable vplace_470, Variable vspadlen_471
where
not func_0(vsbuffer_461, vbuffer_462, vcurrlen_463, vmaxlen_464)
and not func_1(vsbuffer_461, vbuffer_462, vcurrlen_463, vmaxlen_464, vsignvalue_466)
and not func_2(vsbuffer_461, vbuffer_462, vcurrlen_463, vmaxlen_464)
and not func_3(vsbuffer_461, vbuffer_462, vcurrlen_463, vmaxlen_464)
and not func_4(vsbuffer_461, vbuffer_462, vcurrlen_463, vmaxlen_464)
and func_7(vprefix_467)
and func_8(vconvert_469, vplace_470)
and func_9(vspadlen_471)
and func_14(func)
and func_28(func)
and func_38(vsbuffer_461, vbuffer_462, vcurrlen_463, vmaxlen_464)
and func_39(vsbuffer_461, vbuffer_462, vcurrlen_463, vmaxlen_464, vsignvalue_466)
and func_40(vsbuffer_461, vbuffer_462, vcurrlen_463, vmaxlen_464)
and func_41(vsbuffer_461, vbuffer_462, vcurrlen_463, vmaxlen_464)
and func_42(vsbuffer_461, vbuffer_462, vcurrlen_463, vmaxlen_464, vplace_470)
and vsbuffer_461.getType().hasName("char **")
and vbuffer_462.getType().hasName("char **")
and vcurrlen_463.getType().hasName("size_t *")
and vmaxlen_464.getType().hasName("size_t *")
and vsignvalue_466.getType().hasName("int")
and vprefix_467.getType().hasName("const char *")
and vconvert_469.getType().hasName("char[26]")
and vplace_470.getType().hasName("int")
and vspadlen_471.getType().hasName("int")
and vsbuffer_461.getParentScope+() = func
and vbuffer_462.getParentScope+() = func
and vcurrlen_463.getParentScope+() = func
and vmaxlen_464.getParentScope+() = func
and vsignvalue_466.getParentScope+() = func
and vprefix_467.getParentScope+() = func
and vconvert_469.getParentScope+() = func
and vplace_470.getParentScope+() = func
and vspadlen_471.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
