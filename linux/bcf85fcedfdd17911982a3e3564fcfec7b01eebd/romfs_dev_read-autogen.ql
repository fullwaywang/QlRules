/**
 * @name linux-bcf85fcedfdd17911982a3e3564fcfec7b01eebd-romfs_dev_read
 * @id cpp/linux/bcf85fcedfdd17911982a3e3564fcfec7b01eebd/romfs-dev-read
 * @description linux-bcf85fcedfdd17911982a3e3564fcfec7b01eebd-romfs_dev_read 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vpos_214, Variable vlimit_217) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vpos_214
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vlimit_217
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5")
}

predicate func_2(Parameter vpos_214, Parameter vbuflen_215, Variable vlimit_217) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vbuflen_215
		and target_2.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit_217
		and target_2.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vpos_214
		and target_2.getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_3(Parameter vpos_214, Parameter vbuflen_215, Variable vlimit_217, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition() instanceof RelationalOperation
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuflen_215
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit_217
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vpos_214
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

from Function func, Parameter vpos_214, Parameter vbuflen_215, Variable vlimit_217
where
not func_0(func)
and func_1(vpos_214, vlimit_217)
and func_2(vpos_214, vbuflen_215, vlimit_217)
and func_3(vpos_214, vbuflen_215, vlimit_217, func)
and vpos_214.getType().hasName("unsigned long")
and vbuflen_215.getType().hasName("size_t")
and vlimit_217.getType().hasName("size_t")
and vpos_214.getParentScope+() = func
and vbuflen_215.getParentScope+() = func
and vlimit_217.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
