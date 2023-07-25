/**
 * @name ffmpeg-fd30e4d57fe5841385f845440688505b88c0f4a9-mov_read_hdlr
 * @id cpp/ffmpeg/fd30e4d57fe5841385f845440688505b88c0f4a9/mov-read-hdlr
 * @description ffmpeg-fd30e4d57fe5841385f845440688505b88c0f4a9-libavformat/mov.c-mov_read_hdlr CVE-2017-5025
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtitle_size_707, RelationalOperation target_1, AddExpr target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtitle_size_707
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getValue()="2147483647"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtitle_size_707, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vtitle_size_707
		and target_1.getLesserOperand().(Literal).getValue()="0"
}

predicate func_2(Variable vtitle_size_707, AddExpr target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vtitle_size_707
		and target_2.getAnOperand().(Literal).getValue()="1"
}

from Function func, Variable vtitle_size_707, RelationalOperation target_1, AddExpr target_2
where
not func_0(vtitle_size_707, target_1, target_2)
and func_1(vtitle_size_707, target_1)
and func_2(vtitle_size_707, target_2)
and vtitle_size_707.getType().hasName("int64_t")
and vtitle_size_707.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
