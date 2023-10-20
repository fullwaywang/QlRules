/**
 * @name vim-0c8485f0e4931463c0f7986e1ea84a7d79f10c75-unserialize_uep
 * @id cpp/vim/0c8485f0e4931463c0f7986e1ea84a7d79f10c75/unserialize-uep
 * @description vim-0c8485f0e4931463c0f7986e1ea84a7d79f10c75-src/undo.c-unserialize_uep CVE-2017-6350
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Initializer target_0 |
		target_0.getExpr() instanceof Literal
		and target_0.getExpr().getEnclosingFunction() = func)
}

predicate func_1(Variable vuep_1387, RelationalOperation target_5, MulExpr target_6) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="ue_size"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vuep_1387
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getValue()="1152921504606846975"
		and target_1.getThen() instanceof ExprStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vuep_1387, Variable varray_1388, RelationalOperation target_5, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=varray_1388
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lalloc")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(SizeofTypeOperator).getValue()="8"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="ue_size"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vuep_1387
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_4(Variable varray_1388, RelationalOperation target_5, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=varray_1388
		and target_4.getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_4.getParent().(IfStmt).getCondition()=target_5
}

predicate func_5(Variable vuep_1387, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="ue_size"
		and target_5.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vuep_1387
		and target_5.getLesserOperand().(Literal).getValue()="0"
}

predicate func_6(Variable vuep_1387, MulExpr target_6) {
		target_6.getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_6.getLeftOperand().(SizeofTypeOperator).getValue()="8"
		and target_6.getRightOperand().(PointerFieldAccess).getTarget().getName()="ue_size"
		and target_6.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vuep_1387
}

from Function func, Variable vuep_1387, Variable varray_1388, ExprStmt target_2, ExprStmt target_4, RelationalOperation target_5, MulExpr target_6
where
not func_0(func)
and not func_1(vuep_1387, target_5, target_6)
and func_2(vuep_1387, varray_1388, target_5, target_2)
and func_4(varray_1388, target_5, target_4)
and func_5(vuep_1387, target_5)
and func_6(vuep_1387, target_6)
and vuep_1387.getType().hasName("u_entry_T *")
and varray_1388.getType().hasName("char_u **")
and vuep_1387.getParentScope+() = func
and varray_1388.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
