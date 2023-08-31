/**
 * @name postgresql-f0c7b789ab12fbc8248b671c7882dd96ac932ef4-ExecEvalCase
 * @id cpp/postgresql/f0c7b789ab12fbc8248b671c7882dd96ac932ef4/ExecEvalCase
 * @description postgresql-f0c7b789ab12fbc8248b671c7882dd96ac932ef4-src/backend/executor/execQual.c-ExecEvalCase CVE-2016-5423
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vecontext_2960, ExprStmt target_8, ExprStmt target_9) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="caseValue_isNull"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecontext_2960
		and target_1.getRValue().(VariableAccess).getType().hasName("bool")
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vecontext_2960, Variable vwclause_2995, Variable vclause_value_2996, AddressOfExpr target_10, ExprStmt target_11, PointerDereferenceExpr target_13, LogicalAndExpr target_15) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vclause_value_2996
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="evalfunc"
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="expr"
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwclause_2995
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwclause_2995
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vecontext_2960
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(3).(Literal).getValue()="0"
		and target_10.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vecontext_2960, Parameter visNull_2961, Variable vwclause_2995) {
	exists(AddressOfExpr target_3 |
		target_3.getOperand().(VariableAccess).getType().hasName("bool")
		and target_3.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="evalfunc"
		and target_3.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="expr"
		and target_3.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwclause_2995
		and target_3.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_3.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwclause_2995
		and target_3.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vecontext_2960
		and target_3.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(2).(VariableAccess).getTarget()=visNull_2961
		and target_3.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(3).(Literal).getValue()="0")
}

*/
predicate func_5(Parameter vecontext_2960, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="caseValue_isNull"
		and target_5.getQualifier().(VariableAccess).getTarget()=vecontext_2960
		and target_5.getParent().(AddressOfExpr).getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="evalfunc"
		and target_5.getParent().(AddressOfExpr).getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="arg"
		and target_5.getParent().(AddressOfExpr).getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("CaseExprState *")
		and target_5.getParent().(AddressOfExpr).getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="arg"
		and target_5.getParent().(AddressOfExpr).getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("CaseExprState *")
		and target_5.getParent().(AddressOfExpr).getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vecontext_2960
		and target_5.getParent().(AddressOfExpr).getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_6(Parameter vecontext_2960, Parameter visNull_2961, Variable vwclause_2995, AddressOfExpr target_10, ExprStmt target_11, LogicalAndExpr target_15, VariableAccess target_6) {
		target_6.getTarget()=visNull_2961
		and target_6.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="evalfunc"
		and target_6.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="expr"
		and target_6.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwclause_2995
		and target_6.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_6.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwclause_2995
		and target_6.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vecontext_2960
		and target_6.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(3).(Literal).getValue()="0"
		and target_10.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getLocation())
		and target_6.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_7(Parameter visNull_2961, PointerDereferenceExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=visNull_2961
}

predicate func_8(Parameter vecontext_2960, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="caseValue_datum"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecontext_2960
		and target_8.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="evalfunc"
		and target_8.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="arg"
		and target_8.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("CaseExprState *")
		and target_8.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="arg"
		and target_8.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("CaseExprState *")
		and target_8.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vecontext_2960
		and target_8.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="caseValue_isNull"
		and target_8.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecontext_2960
		and target_8.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_9(Parameter vecontext_2960, Parameter visNull_2961, Variable vwclause_2995, Variable vclause_value_2996, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vclause_value_2996
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="evalfunc"
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="expr"
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwclause_2995
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwclause_2995
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vecontext_2960
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(VariableAccess).getTarget()=visNull_2961
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_10(Parameter vecontext_2960, AddressOfExpr target_10) {
		target_10.getOperand().(PointerFieldAccess).getTarget().getName()="caseValue_isNull"
		and target_10.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecontext_2960
}

predicate func_11(Parameter vecontext_2960, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="caseValue_datum"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecontext_2960
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("Datum")
}

predicate func_13(Variable vwclause_2995, PointerDereferenceExpr target_13) {
		target_13.getOperand().(PointerFieldAccess).getTarget().getName()="evalfunc"
		and target_13.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="result"
		and target_13.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwclause_2995
}

predicate func_15(Variable vclause_value_2996, LogicalAndExpr target_15) {
		target_15.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vclause_value_2996
		and target_15.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="255"
		and target_15.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_15.getAnOperand().(NotExpr).getOperand() instanceof PointerDereferenceExpr
}

from Function func, Parameter vecontext_2960, Parameter visNull_2961, Variable vwclause_2995, Variable vclause_value_2996, PointerFieldAccess target_5, VariableAccess target_6, PointerDereferenceExpr target_7, ExprStmt target_8, ExprStmt target_9, AddressOfExpr target_10, ExprStmt target_11, PointerDereferenceExpr target_13, LogicalAndExpr target_15
where
not func_1(vecontext_2960, target_8, target_9)
and not func_2(vecontext_2960, vwclause_2995, vclause_value_2996, target_10, target_11, target_13, target_15)
and func_5(vecontext_2960, target_5)
and func_6(vecontext_2960, visNull_2961, vwclause_2995, target_10, target_11, target_15, target_6)
and func_7(visNull_2961, target_7)
and func_8(vecontext_2960, target_8)
and func_9(vecontext_2960, visNull_2961, vwclause_2995, vclause_value_2996, target_9)
and func_10(vecontext_2960, target_10)
and func_11(vecontext_2960, target_11)
and func_13(vwclause_2995, target_13)
and func_15(vclause_value_2996, target_15)
and vecontext_2960.getType().hasName("ExprContext *")
and visNull_2961.getType().hasName("bool *")
and vwclause_2995.getType().hasName("CaseWhenState *")
and vclause_value_2996.getType().hasName("Datum")
and vecontext_2960.getFunction() = func
and visNull_2961.getFunction() = func
and vwclause_2995.(LocalVariable).getFunction() = func
and vclause_value_2996.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
