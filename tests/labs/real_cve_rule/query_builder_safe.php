<?php
foreach ($this->binds as $field => $bind) {
    $escaped = $bind[1] ? $this->db->escape($bind[0]) : $bind[0];
    $replacers[':' . $field . ':'] = (string) $escaped;
}
foreach ($this->QBWhere as $key => $where) {
    $this->QBWhere[$key]['condition'] = strtr($where['condition'], $replacers);
}
