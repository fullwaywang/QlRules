/**
 * @name linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-xlvbd_flush
 * @id cpp/linux/e35e5b6f695d241ffb1d223207da58a1fbcdff4b/xlvbd-flush
 * @description linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-xlvbd_flush CVE-2022-26365
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="6blkfront: %s: %s %s %s %s %s\n"
		and not target_0.getValue()="6blkfront: %s: %s %s %s %s %s %s %s\n"
		and target_0.getEnclosingFunction() = func)
}

predicate func_3(Parameter vinfo_980) {
	exists(ConditionalExpr target_3 |
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="bounce"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_980
		and target_3.getThen().(StringLiteral).getValue()="enabled"
		and target_3.getElse().(StringLiteral).getValue()="disabled;"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_printk")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="6blkfront: %s: %s %s %s %s %s %s %s\n"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="disk_name"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="gd"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_980
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("flush_info")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfo_980
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="persistent grants:"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="feature_persistent"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_980
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(StringLiteral).getValue()="enabled;"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getElse().(StringLiteral).getValue()="disabled;"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="indirect descriptors:"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="max_indirect_segments"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_980
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ConditionalExpr).getThen().(StringLiteral).getValue()="enabled;"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ConditionalExpr).getElse().(StringLiteral).getValue()="disabled;"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(StringLiteral).getValue()="bounce buffer:")
}

predicate func_4(Parameter vinfo_980) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="max_indirect_segments"
		and target_4.getQualifier().(VariableAccess).getTarget()=vinfo_980)
}

from Function func, Parameter vinfo_980
where
func_0(func)
and not func_3(vinfo_980)
and vinfo_980.getType().hasName("blkfront_info *")
and func_4(vinfo_980)
and vinfo_980.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
