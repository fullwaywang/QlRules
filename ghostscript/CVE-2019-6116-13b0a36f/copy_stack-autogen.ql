/**
 * @name ghostscript-13b0a36f-copy_stack
 * @id cpp/ghostscript/13b0a36f/copy-stack
 * @description ghostscript-13b0a36f-psi/interp.c-copy_stack CVE-2019-6116
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vi_ctx_p_795, Parameter vpstack_795, Parameter varr_795, Variable vcode_799, AddressOfExpr target_1, EqualityOperation target_2, AddressOfExpr target_3, ExprStmt target_4, ReturnStmt target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpstack_795
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("dict_find_string")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("dict_find_string")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("ref *")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="safe"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="boolval"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ref *")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_799
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ref_stack_array_sanitize")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_795
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=varr_795
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=varr_795
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcode_799
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_799
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_3.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vi_ctx_p_795, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_795
}

predicate func_2(Parameter vi_ctx_p_795, Parameter vpstack_795, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vpstack_795
		and target_2.getAnOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="stack"
		and target_2.getAnOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="exec_stack"
		and target_2.getAnOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_795
}

predicate func_3(Parameter varr_795, AddressOfExpr target_3) {
		target_3.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="refs"
		and target_3.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_3.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=varr_795
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_4(Parameter vi_ctx_p_795, Parameter vpstack_795, Parameter varr_795, Variable vcode_799, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_799
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ref_stack_store")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpstack_795
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=varr_795
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("uint")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="1"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="1"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_795
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(StringLiteral).getValue()="copy_stack"
}

predicate func_5(Variable vcode_799, ReturnStmt target_5) {
		target_5.getExpr().(VariableAccess).getTarget()=vcode_799
}

from Function func, Parameter vi_ctx_p_795, Parameter vpstack_795, Parameter varr_795, Variable vcode_799, AddressOfExpr target_1, EqualityOperation target_2, AddressOfExpr target_3, ExprStmt target_4, ReturnStmt target_5
where
not func_0(vi_ctx_p_795, vpstack_795, varr_795, vcode_799, target_1, target_2, target_3, target_4, target_5, func)
and func_1(vi_ctx_p_795, target_1)
and func_2(vi_ctx_p_795, vpstack_795, target_2)
and func_3(varr_795, target_3)
and func_4(vi_ctx_p_795, vpstack_795, varr_795, vcode_799, target_4)
and func_5(vcode_799, target_5)
and vi_ctx_p_795.getType().hasName("i_ctx_t *")
and vpstack_795.getType().hasName("const ref_stack_t *")
and varr_795.getType().hasName("ref *")
and vcode_799.getType().hasName("int")
and vi_ctx_p_795.getFunction() = func
and vpstack_795.getFunction() = func
and varr_795.getFunction() = func
and vcode_799.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
