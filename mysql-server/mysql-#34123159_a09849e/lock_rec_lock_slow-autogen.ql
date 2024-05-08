/**
 * @name mysql-server-a09849ebc036a0155d9137981137f574c8621716-lock_rec_lock_slow
 * @id cpp/mysql-server/a09849ebc036a0155d9137981137f574c8621716/lockreclockslow
 * @description mysql-server-a09849ebc036a0155d9137981137f574c8621716-storage/innobase/lock/lock0lock.cc-lock_rec_lock_slow mysql-#34123159
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmode_1792, Parameter vblock_1793, Parameter vheap_no_1793, Variable vtrx_1809, Initializer target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getExpr() |
		obj_0.getTarget().hasName("lock_rec_other_has_conflicting")
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vmode_1792
		and obj_0.getArgument(1).(VariableAccess).getTarget()=vblock_1793
		and obj_0.getArgument(2).(VariableAccess).getTarget()=vheap_no_1793
		and obj_0.getArgument(3).(VariableAccess).getTarget()=vtrx_1809
	)
}

predicate func_2(Function func) {
exists(ValueFieldAccess target_2 |
	target_2.getTarget().getName()="wait_for"
	and target_2.getQualifier().(VariableAccess).getType().hasName("const Conflicting")
	and target_2.getEnclosingFunction() = func
)
}

predicate func_3(Function func) {
exists(ValueFieldAccess target_3 |
	target_3.getTarget().getName()="wait_for"
	and target_3.getQualifier().(VariableAccess).getType().hasName("const Conflicting")
	and target_3.getEnclosingFunction() = func
)
}

predicate func_4(BlockStmt target_9, Function func) {
exists(LogicalOrExpr target_4 |
	exists(ValueFieldAccess obj_0 | obj_0=target_4.getRightOperand() |
		obj_0.getTarget().getName()="bypassed"
		and obj_0.getQualifier().(VariableAccess).getType().hasName("const Conflicting")
	)
	and target_4.getLeftOperand() instanceof NotExpr
	and target_4.getParent().(IfStmt).getThen()=target_9
	and target_4.getEnclosingFunction() = func
)
}

predicate func_5(Parameter vimpl_1792, BlockStmt target_9, NotExpr target_5) {
	target_5.getOperand().(VariableAccess).getTarget()=vimpl_1792
	and target_5.getParent().(IfStmt).getThen()=target_9
}

predicate func_7(Variable vwait_for_1851, BlockStmt target_10, FunctionCall target_12, VariableAccess target_7) {
	exists(NEExpr obj_0 | obj_0=target_7.getParent() |
		obj_0.getRightOperand().(Literal).getValue()="0"
		and obj_0.getParent().(IfStmt).getThen()=target_10
	)
	and target_7.getTarget()=vwait_for_1851
	and target_7.getLocation().isBefore(target_12.getArgument(0).(VariableAccess).getLocation())
}

predicate func_8(Variable vwait_for_1851, EqualityOperation target_13, VariableAccess target_8) {
	exists(FunctionCall obj_0 | obj_0=target_8.getParent() |
		exists(Initializer obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				obj_2.getTarget().hasName("add_to_waitq")
				and obj_2.getQualifier().(VariableAccess).getTarget().getType().hasName("RecLock")
			)
		)
	)
	and target_8.getTarget()=vwait_for_1851
	and target_13.getLeftOperand().(VariableAccess).getLocation().isBefore(target_8.getLocation())
}

predicate func_9(Parameter vmode_1792, Parameter vblock_1793, Parameter vheap_no_1793, Variable vtrx_1809, BlockStmt target_9) {
	exists(ExprStmt obj_0 | obj_0=target_9.getStmt(0) |
		exists(FunctionCall obj_1 | obj_1=obj_0.getExpr() |
			exists(BitwiseOrExpr obj_2 | obj_2=obj_1.getArgument(0) |
				obj_2.getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
				and obj_2.getRightOperand().(VariableAccess).getTarget()=vmode_1792
			)
			and obj_1.getTarget().hasName("lock_rec_add_to_queue")
			and obj_1.getArgument(1).(VariableAccess).getTarget()=vblock_1793
			and obj_1.getArgument(2).(VariableAccess).getTarget()=vheap_no_1793
			and obj_1.getArgument(3).(VariableAccess).getTarget().getType().hasName("dict_index_t *")
			and obj_1.getArgument(4).(VariableAccess).getTarget()=vtrx_1809
		)
	)
}

predicate func_10(Function func, BlockStmt target_10) {
	exists(SwitchStmt obj_0 | obj_0=target_10.getStmt(0) |
		exists(BlockStmt obj_1 | obj_1=obj_0.getStmt() |
			exists(DoStmt obj_2 | obj_2=obj_1.getStmt(6) |
				obj_2.getCondition().(Literal).getValue()="0"
				and obj_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mutex_enter_inline")
			)
			and exists(DoStmt obj_3 | obj_3=obj_1.getStmt(8) |
				obj_3.getCondition().(Literal).getValue()="0"
				and obj_3.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
			)
			and obj_1.getStmt(10).(ReturnStmt).getExpr().(VariableAccess).getTarget().getType().hasName("dberr_t")
		)
		and obj_0.getExpr().(VariableAccess).getTarget().getType().hasName("select_mode")
	)
	and target_10.getEnclosingFunction() = func
}

predicate func_12(Variable vwait_for_1851, FunctionCall target_12) {
	target_12.getTarget().hasName("add_to_waitq")
	and target_12.getQualifier().(VariableAccess).getTarget().getType().hasName("RecLock")
	and target_12.getArgument(0).(VariableAccess).getTarget()=vwait_for_1851
}

predicate func_13(Variable vwait_for_1851, EqualityOperation target_13) {
	target_13.getLeftOperand().(VariableAccess).getTarget()=vwait_for_1851
	and target_13.getRightOperand().(Literal).getValue()="0"
}

from Function func, Parameter vmode_1792, Parameter vblock_1793, Parameter vheap_no_1793, Variable vtrx_1809, Variable vwait_for_1851, Parameter vimpl_1792, Initializer target_0, NotExpr target_5, VariableAccess target_7, VariableAccess target_8, BlockStmt target_9, BlockStmt target_10, FunctionCall target_12, EqualityOperation target_13
where
func_0(vmode_1792, vblock_1793, vheap_no_1793, vtrx_1809, target_0)
and not func_2(func)
and not func_3(func)
and not func_4(target_9, func)
and func_5(vimpl_1792, target_9, target_5)
and func_7(vwait_for_1851, target_10, target_12, target_7)
and func_8(vwait_for_1851, target_13, target_8)
and func_9(vmode_1792, vblock_1793, vheap_no_1793, vtrx_1809, target_9)
and func_10(func, target_10)
and func_12(vwait_for_1851, target_12)
and func_13(vwait_for_1851, target_13)
and vmode_1792.getType().hasName("ulint")
and vblock_1793.getType().hasName("const buf_block_t *")
and vheap_no_1793.getType().hasName("ulint")
and vtrx_1809.getType().hasName("trx_t *")
and vwait_for_1851.getType().hasName("const ib_lock_t *")
and vimpl_1792.getType().hasName("bool")
and vmode_1792.getFunction() = func
and vblock_1793.getFunction() = func
and vheap_no_1793.getFunction() = func
and vtrx_1809.(LocalVariable).getFunction() = func
and vwait_for_1851.(LocalVariable).getFunction() = func
and vimpl_1792.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
