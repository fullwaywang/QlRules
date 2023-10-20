/**
 * @name neomutt-9bfab35522301794483f8f9ed60820bdec9be59e-pop_fetch_message
 * @id cpp/neomutt/9bfab35522301794483f8f9ed60820bdec9be59e/pop-fetch-message
 * @description neomutt-9bfab35522301794483f8f9ed60820bdec9be59e-pop.c-pop_fetch_message CVE-2018-14362
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vh_596, ExprStmt target_6) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("cache_id")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_596
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(RemExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vh_596, SubExpr target_7, ExprStmt target_8) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("cache_id")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_596
		and target_7.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vh_596, ExprStmt target_8, ExprStmt target_9) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("cache_id")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_596
		and target_8.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vh_596, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="data"
		and target_3.getQualifier().(VariableAccess).getTarget()=vh_596
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mutt_bcache_get")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="bcache"
}

predicate func_4(Variable vh_596, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="data"
		and target_4.getQualifier().(VariableAccess).getTarget()=vh_596
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mutt_bcache_put")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="bcache"
}

predicate func_5(Variable vh_596, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="data"
		and target_5.getQualifier().(VariableAccess).getTarget()=vh_596
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mutt_bcache_commit")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="bcache"
}

predicate func_6(Variable vh_596, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cache"
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(RemExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="index"
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(RemExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_596
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(RemExpr).getRightOperand().(Literal).getValue()="10"
}

predicate func_7(Variable vh_596, SubExpr target_7) {
		target_7.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_7.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="content"
		and target_7.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_596
		and target_7.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset"
		and target_7.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="content"
		and target_7.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_596
		and target_7.getRightOperand().(Literal).getValue()="1"
}

predicate func_8(Variable vh_596, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_8.getExpr().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1024"
		and target_8.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="RETR %d\r\n"
		and target_8.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="refno"
		and target_8.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_596
}

predicate func_9(Variable vh_596, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="index"
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="index"
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_596
}

from Function func, Variable vh_596, PointerFieldAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, ExprStmt target_6, SubExpr target_7, ExprStmt target_8, ExprStmt target_9
where
not func_0(vh_596, target_6)
and not func_1(vh_596, target_7, target_8)
and not func_2(vh_596, target_8, target_9)
and func_3(vh_596, target_3)
and func_4(vh_596, target_4)
and func_5(vh_596, target_5)
and func_6(vh_596, target_6)
and func_7(vh_596, target_7)
and func_8(vh_596, target_8)
and func_9(vh_596, target_9)
and vh_596.getType().hasName("Header *")
and vh_596.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
