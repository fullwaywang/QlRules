/**
 * @name opusfile-0a4cd796df5b030cb866f3f4a5e41a4b92caddf5-op_get_data
 * @id cpp/opusfile/0a4cd796df5b030cb866f3f4a5e41a4b92caddf5/op-get-data
 * @description opusfile-0a4cd796df5b030cb866f3f4a5e41a4b92caddf5-src/opusfile.c-op_get_data CVE-2022-47021
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuffer_147, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuffer_147
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-129"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vbuffer_147, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffer_147
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ogg_sync_buffer")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="oy"
}

predicate func_2(Variable vbuffer_147, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="read"
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="callbacks"
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="stream"
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_147
}

from Function func, Variable vbuffer_147, ExprStmt target_1, ExprStmt target_2
where
not func_0(vbuffer_147, target_1, target_2, func)
and func_1(vbuffer_147, target_1)
and func_2(vbuffer_147, target_2)
and vbuffer_147.getType().hasName("unsigned char *")
and vbuffer_147.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
