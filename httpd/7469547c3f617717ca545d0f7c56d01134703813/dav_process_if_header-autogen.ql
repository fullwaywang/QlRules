/**
 * @name httpd-7469547c3f617717ca545d0f7c56d01134703813-dav_process_if_header
 * @id cpp/httpd/7469547c3f617717ca545d0f7c56d01134703813/dav-process-if-header
 * @description httpd-7469547c3f617717ca545d0f7c56d01134703813-modules/dav/main/util.c-dav_process_if_header CVE-2006-20001
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vr_669, LogicalAndExpr target_2, FunctionCall target_3, FunctionCall target_4) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("dav_new_error")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_669
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="400"
		and target_0.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="102"
		and target_0.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Invalid \"If:\" header: Unexpected character in List"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlist_673, PointerDereferenceExpr target_5, ExprStmt target_1) {
		target_1.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vlist_673
		and target_1.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
}

predicate func_2(Variable vlist_673, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vlist_673
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="111"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vlist_673
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="116"
}

predicate func_3(Parameter vr_669, FunctionCall target_3) {
		target_3.getTarget().hasName("dav_new_error")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_669
		and target_3.getArgument(1).(Literal).getValue()="400"
		and target_3.getArgument(2).(Literal).getValue()="101"
		and target_3.getArgument(3).(Literal).getValue()="0"
		and target_3.getArgument(4).(StringLiteral).getValue()="Invalid \"If:\" header: Multiple \"not\" entries for the same state."
}

predicate func_4(Variable vlist_673, Parameter vr_669, FunctionCall target_4) {
		target_4.getTarget().hasName("dav_new_error")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_669
		and target_4.getArgument(1).(Literal).getValue()="400"
		and target_4.getArgument(2).(Literal).getValue()="102"
		and target_4.getArgument(3).(Literal).getValue()="0"
		and target_4.getArgument(4).(FunctionCall).getTarget().hasName("apr_psprintf")
		and target_4.getArgument(4).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_4.getArgument(4).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_669
		and target_4.getArgument(4).(FunctionCall).getArgument(1).(StringLiteral).getValue()="Invalid \"If:\" header: Unexpected character encountered (0x%02x, '%c')."
		and target_4.getArgument(4).(FunctionCall).getArgument(2).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlist_673
		and target_4.getArgument(4).(FunctionCall).getArgument(3).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlist_673
}

predicate func_5(Variable vlist_673, PointerDereferenceExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vlist_673
}

from Function func, Variable vlist_673, Parameter vr_669, ExprStmt target_1, LogicalAndExpr target_2, FunctionCall target_3, FunctionCall target_4, PointerDereferenceExpr target_5
where
not func_0(vr_669, target_2, target_3, target_4)
and func_1(vlist_673, target_5, target_1)
and func_2(vlist_673, target_2)
and func_3(vr_669, target_3)
and func_4(vlist_673, vr_669, target_4)
and func_5(vlist_673, target_5)
and vlist_673.getType().hasName("char *")
and vr_669.getType().hasName("request_rec *")
and vlist_673.(LocalVariable).getFunction() = func
and vr_669.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
