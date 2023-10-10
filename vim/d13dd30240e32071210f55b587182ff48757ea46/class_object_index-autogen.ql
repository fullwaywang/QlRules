/**
 * @name vim-d13dd30240e32071210f55b587182ff48757ea46-class_object_index
 * @id cpp/vim/d13dd30240e32071210f55b587182ff48757ea46/class-object-index
 * @description vim-d13dd30240e32071210f55b587182ff48757ea46-src/vim9class.c-class_object_index CVE-2023-1355
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcl_1252, ExprStmt target_1, ConditionalExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcl_1252
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("emsg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("dcgettext")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("char[]")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcl_1252, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcl_1252
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="obj_class"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="v_object"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vval"
}

predicate func_2(Variable vcl_1252, ConditionalExpr target_2) {
		target_2.getThen().(PointerFieldAccess).getTarget().getName()="class_class_function_count"
		and target_2.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcl_1252
		and target_2.getElse().(PointerFieldAccess).getTarget().getName()="class_obj_method_count"
		and target_2.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcl_1252
}

from Function func, Variable vcl_1252, ExprStmt target_1, ConditionalExpr target_2
where
not func_0(vcl_1252, target_1, target_2, func)
and func_1(vcl_1252, target_1)
and func_2(vcl_1252, target_2)
and vcl_1252.getType().hasName("class_T *")
and vcl_1252.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
