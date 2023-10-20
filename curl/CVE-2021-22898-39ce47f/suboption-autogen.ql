/**
 * @name curl-39ce47f219b09c380b81f89fe54ac586c8db6bde-suboption
 * @id cpp/curl/39ce47f219b09c380b81f89fe54ac586c8db6bde/suboption
 * @description curl-39ce47f219b09c380b81f89fe54ac586c8db6bde-lib/telnet.c-suboption CVE-2021-22898
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_2, Function func) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand() instanceof FunctionCall
		and target_0.getAnOperand().(Literal).getValue()="2"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vv_879, Variable vvarname_884, Variable vvarval_885, BlockStmt target_2, FunctionCall target_1) {
		target_1.getTarget().hasName("sscanf")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_879
		and target_1.getArgument(1).(StringLiteral).getValue()="%127[^,],%127s"
		and target_1.getArgument(2).(VariableAccess).getTarget()=vvarname_884
		and target_1.getArgument(3).(VariableAccess).getTarget()=vvarval_885
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vvarname_884, Variable vvarval_885, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("curl_msnprintf")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("unsigned char[2048]")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(SizeofExprOperator).getValue()="2048"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%c%s%c%s"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvarname_884
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="1"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vvarval_885
}

from Function func, Variable vv_879, Variable vvarname_884, Variable vvarval_885, FunctionCall target_1, BlockStmt target_2
where
not func_0(target_2, func)
and func_1(vv_879, vvarname_884, vvarval_885, target_2, target_1)
and func_2(vvarname_884, vvarval_885, target_2)
and vv_879.getType().hasName("curl_slist *")
and vvarname_884.getType().hasName("char[128]")
and vvarval_885.getType().hasName("char[128]")
and vv_879.(LocalVariable).getFunction() = func
and vvarname_884.(LocalVariable).getFunction() = func
and vvarval_885.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
