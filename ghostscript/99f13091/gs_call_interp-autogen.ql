/**
 * @name ghostscript-99f13091-gs_call_interp
 * @id cpp/ghostscript/99f13091/gs-call-interp
 * @description ghostscript-99f13091-psi/interp.c-gs_call_interp CVE-2019-6116
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcode_493, BlockStmt target_4, ExprStmt target_5) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vcode_493
		and target_0.getGreaterOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcode_493, BlockStmt target_4, VariableAccess target_1) {
		target_1.getTarget()=vcode_493
		and target_1.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable vcode_493, BlockStmt target_4, ExprStmt target_5, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vcode_493
		and target_3.getGreaterOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(VariableAccess).getLocation())
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("byte[260]")
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("byte[260]")
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("byte[260]")
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AssignExpr).getRValue().(AssignExpr).getRValue().(CharLiteral).getValue()="45"
}

predicate func_5(Variable vcode_493, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_493
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dict_find_string")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="system_dict"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dict_stack"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("i_ctx_t *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("byte *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("ref *")
}

from Function func, Variable vcode_493, VariableAccess target_1, RelationalOperation target_3, BlockStmt target_4, ExprStmt target_5
where
not func_0(vcode_493, target_4, target_5)
and func_1(vcode_493, target_4, target_1)
and func_3(vcode_493, target_4, target_5, target_3)
and func_4(target_4)
and func_5(vcode_493, target_5)
and vcode_493.getType().hasName("int")
and vcode_493.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
