/**
 * @name libgit2-1f9a8510e1d2f20ed7334eeeddb92c4dd8e7c649-ng_pkt
 * @id cpp/libgit2/1f9a8510e1d2f20ed7334eeeddb92c4dd8e7c649/ng-pkt
 * @description libgit2-1f9a8510e1d2f20ed7334eeeddb92c4dd8e7c649-src/transports/smart_pkt.c-ng_pkt CVE-2018-15501
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_290, GotoStmt target_13) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vlen_290
		and target_0.getGreaterOperand().(Literal).getValue()="3"
		and target_0.getParent().(IfStmt).getThen()=target_13)
}

predicate func_1(Parameter vlen_290, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vlen_290
		and target_1.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="3"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vline_290, Parameter vlen_290, ExprStmt target_14, ExprStmt target_15) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("memchr")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vline_290
		and target_2.getArgument(1) instanceof CharLiteral
		and target_2.getArgument(2).(VariableAccess).getTarget()=vlen_290
		and target_14.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(VariableAccess).getLocation())
		and target_2.getArgument(0).(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vlen_290, ExprStmt target_16, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_290
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_3.getThen().(GotoStmt).toString() = "goto ..."
		and target_3.getThen().(GotoStmt).getName() ="out_err"
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_3)
		and target_16.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vlen_290, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vlen_290
		and target_4.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_4))
}

predicate func_5(Parameter vline_290, Parameter vlen_290, Variable vptr_293, ExprStmt target_17, ExprStmt target_18, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(NotExpr).getOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_293
		and target_5.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("memchr")
		and target_5.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_290
		and target_5.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof CharLiteral
		and target_5.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_290
		and target_5.getThen().(GotoStmt).toString() = "goto ..."
		and target_5.getThen().(GotoStmt).getName() ="out_err"
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_5)
		and target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation()))
}

/*predicate func_6(Parameter vline_290, Parameter vlen_290, ExprStmt target_17, ExprStmt target_18) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("memchr")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vline_290
		and target_6.getArgument(1) instanceof CharLiteral
		and target_6.getArgument(2).(VariableAccess).getTarget()=vlen_290
		and target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getArgument(0).(VariableAccess).getLocation())
		and target_6.getArgument(0).(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation()))
}

*/
predicate func_7(Parameter vline_290, VariableAccess target_7) {
		target_7.getTarget()=vline_290
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_9(Parameter vline_290, VariableAccess target_9) {
		target_9.getTarget()=vline_290
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_11(Parameter vline_290, FunctionCall target_11) {
		target_11.getTarget().hasName("strchr")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vline_290
		and target_11.getArgument(1) instanceof CharLiteral
}

predicate func_12(Parameter vline_290, FunctionCall target_12) {
		target_12.getTarget().hasName("strchr")
		and target_12.getArgument(0).(VariableAccess).getTarget()=vline_290
		and target_12.getArgument(1) instanceof CharLiteral
}

predicate func_13(GotoStmt target_13) {
		target_13.toString() = "goto ..."
		and target_13.getName() ="out_err"
}

predicate func_14(Parameter vline_290, ExprStmt target_14) {
		target_14.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vline_290
		and target_14.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="3"
}

predicate func_15(Parameter vline_290, Parameter vlen_290, Variable vptr_293, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_290
		and target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vptr_293
		and target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vline_290
}

predicate func_16(Parameter vlen_290, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ref"
		and target_16.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_290
		and target_16.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_17(Parameter vline_290, Variable vptr_293, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vline_290
		and target_17.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr_293
		and target_17.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_18(Parameter vline_290, Parameter vlen_290, Variable vptr_293, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_290
		and target_18.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vptr_293
		and target_18.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vline_290
}

from Function func, Parameter vline_290, Parameter vlen_290, Variable vptr_293, VariableAccess target_7, VariableAccess target_9, FunctionCall target_11, FunctionCall target_12, GotoStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18
where
not func_0(vlen_290, target_13)
and not func_1(vlen_290, func)
and not func_2(vline_290, vlen_290, target_14, target_15)
and not func_3(vlen_290, target_16, func)
and not func_4(vlen_290, func)
and not func_5(vline_290, vlen_290, vptr_293, target_17, target_18, func)
and func_7(vline_290, target_7)
and func_9(vline_290, target_9)
and func_11(vline_290, target_11)
and func_12(vline_290, target_12)
and func_13(target_13)
and func_14(vline_290, target_14)
and func_15(vline_290, vlen_290, vptr_293, target_15)
and func_16(vlen_290, target_16)
and func_17(vline_290, vptr_293, target_17)
and func_18(vline_290, vlen_290, vptr_293, target_18)
and vline_290.getType().hasName("const char *")
and vlen_290.getType().hasName("size_t")
and vptr_293.getType().hasName("const char *")
and vline_290.getParentScope+() = func
and vlen_290.getParentScope+() = func
and vptr_293.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
