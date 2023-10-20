/**
 * @name vim-3eb1637b1bba19519885dd6d377bd5596e91d22c-u_read_undo
 * @id cpp/vim/3eb1637b1bba19519885dd6d377bd5596e91d22c/u-read-undo
 * @description vim-3eb1637b1bba19519885dd6d377bd5596e91d22c-src/undo.c-u_read_undo CVE-2017-6349
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vnum_head_1790, RelationalOperation target_3, MulExpr target_4) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnum_head_1790
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getValue()="1152921504606846975"
		and target_1.getThen() instanceof ExprStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_4.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vnum_head_1790, Variable vuhp_table_1800, RelationalOperation target_3, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vuhp_table_1800
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lalloc")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vnum_head_1790
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="8"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Variable vnum_head_1790, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vnum_head_1790
		and target_3.getLesserOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vnum_head_1790, MulExpr target_4) {
		target_4.getLeftOperand().(VariableAccess).getTarget()=vnum_head_1790
		and target_4.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getRightOperand().(SizeofTypeOperator).getValue()="8"
}

from Function func, Variable vnum_head_1790, Variable vuhp_table_1800, ExprStmt target_2, RelationalOperation target_3, MulExpr target_4
where
not func_1(vnum_head_1790, target_3, target_4)
and func_2(vnum_head_1790, vuhp_table_1800, target_3, target_2)
and func_3(vnum_head_1790, target_3)
and func_4(vnum_head_1790, target_4)
and vnum_head_1790.getType().hasName("int")
and vuhp_table_1800.getType().hasName("u_header_T **")
and vnum_head_1790.getParentScope+() = func
and vuhp_table_1800.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
